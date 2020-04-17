const request = require('request-promise-native');
const uuid4 = require('uuid/v4');
const {memoize, cloneDeep} = require('lodash');

const {dedup, requestWithTimeout, shrink} = require('@raychee/utils');


/**
 * @param cookies A whole string from an http "Cookies" header
 */
function defaultLoadIdentityFn(options, {cookies, userAgent}) {
    if (cookies) {
        if (typeof cookies === 'string') {
            cookies = cookies.split('; ').map(cookie => {
                const [key, value] = cookie.split('=');
                if (key == null) {
                    this.crash('_request_default_load_identity_error', 'invalid cookie: ', cookie);
                }
                return {key, value};
            });
        } else if (Array.isArray(cookies)) {
            // try to be compatible with both tough-cookies and puppeteer cookies
            // https://github.com/salesforce/tough-cookie#serializecberrserializedobject
            // https://pptr.dev/#?product=Puppeteer&version=v2.1.1&show=api-pagecookiesurls
            cookies = cookies.map(cookie => {
                const {name, value, domain, path, expires, key, maxAge, creation} = cookie;
                const ret = shrink({
                    key: key || name, value,
                    maxAge: maxAge || (expires - Date.now() / 1000),
                    domain, path,
                    creation: creation || new Date().toISOString()
                });
                if (ret.key == null) {
                    this.crash('_request_default_load_identity_error', 'invalid cookie: ', cookie);
                }
                return ret;
            })
        } else {
            this.crash('_request_default_load_identity_error', 'invalid cookies: ', cookies);
        }
        const headers = options.headers || {};
        options.headers = headers;
        headers['Cookie'] = cookies.map(c => `${c.key}=${c.value}`).join('; ');
    }
    if (userAgent) {
        const headers = options.headers || {};
        options.headers = headers;
        headers['User-Agent'] = userAgent;
    }
}

function defaultUpdateIdentityFn(options, {identity}) {
    if (identity.cookies) {
        if (options.jar) {
            let jar = options.jar;
            if (jar._jar) jar = jar._jar;
            const cookies = jar.serializeSync().cookies;
            return {...identity, cookies};
        }
    }
}

function defaultValidateIdentityFn() {
}

function defaultValidateProxyFn(options, {response, error}) {
    if (error) return error;
    if (response && (response.statusCode < 200 || response.statusCode >= 400)) return response;
}

function defaultProcessReturnedFn() {
}


module.exports = {
    type: 'request',
    key({defaults, smartError = true, timeout = 0, debug = false, identities, proxies} = {}) {
        if (!identities && !proxies) {
            return {defaults, smartError, timeout, debug};
        }
    },
    create: async function (
        {
            defaults, smartError = true, timeout = 0, debug = false, identities, proxies,
            maxRetryIdentities = 10,
            switchIdentityEvery, switchProxyEvery,
            switchIdentityAfter, switchProxyAfter,
            switchIdentityOnInvalidProxy = false, switchProxyOnInvalidIdentity = true,
            createIdentityFn,
            loadIdentityFn = defaultLoadIdentityFn,
            updateIdentityFn = defaultUpdateIdentityFn,
            validateIdentityFn = defaultValidateIdentityFn,
            validateProxyFn = defaultValidateProxyFn,
            defaultIdentityId,
            loadIdentityError,
            lockIdentityUntilLoaded = false,
            processReturnedFn = defaultProcessReturnedFn,
        } = {},
        {pluginLoader}
    ) {

        let _req = request, jar = request.jar(), extra = {};
        defaults = timeout > 0 ? {timeout: timeout * 1000, ...defaults} : defaults;

        if (timeout > 0) {
            _req = requestWithTimeout(timeout * 1000, _req);
        }

        let req = async function(logger, options) {
            return await _req(options);
        }

        if (smartError) {
            req = async function (req, logger, options) {
                logger = logger || this;
                try {
                    return await req(logger, options);
                } catch (e) {
                    if (e.statusCode) {
                        if (e.statusCode >= 400 && e.statusCode < 500) {
                            logger.crash('_request_status_4xx', e);
                        } else {
                            logger.fail('_request_status_5xx', e);
                        }
                    }
                    if (e.cause) {
                        if (e.cause.code === 'ETIMEDOUT') {
                            logger.fail('_request_timeout', e);
                        } else if (e.cause.code === 'ECONNREFUSED') {
                            logger.fail('_request_connection_refused', e);
                        } else if (e.cause.code === 'ECONNRESET') {
                            logger.fail('_request_connection_reset', e);
                        }
                    }
                    throw e;
                }
            }.bind(this, req);
        }

        if (identities && typeof identities === "object" && identities.constructor === Object) {
            const plugin = await pluginLoader.get({type: 'identities', ...identities});
            identities = plugin.instance;
        }
        if (proxies && typeof proxies === "object" && proxies.constructor === Object) {
            const plugin = await pluginLoader.get({type: 'proxies', ...proxies});
            proxies = plugin.instance;
        }
        if (identities) extra.identities = identities;
        if (proxies) extra.proxies = proxies;
        let identity = undefined, proxy = undefined;
        let counter = 0, lastTimeSwitchIdentity = undefined, lastTimeSwitchProxy = undefined;
        extra.currentIdentity = () => identity;
        extra.currentProxy = () => proxy;

        const getReqWithoutIdentities = memoize(defaultIdentityId => {
            let _req = undefined;
            return async (...args) => {
                if (!_req) {
                    const plugin = await pluginLoader.get({
                        type: 'request',
                        defaults, smartError, timeout, debug, proxies,
                        maxRetryIdentities, switchProxyEvery, switchProxyAfter,
                        validateProxyFn, defaultIdentityId
                    });
                    _req = plugin.instance;
                }
                return await _req(...args);
            };
        });

        async function getIdentity(...args) {
            const old = identity;
            identity = await identities.get(...args);
            if ((old && old.id) !== (identity && identity.id)) {
                lastTimeSwitchIdentity = Date.now();
            }
        }

        async function getProxy(...args) {
            const old = proxy;
            proxy = await proxies.get(...args);
            if (old !== proxy) {
                lastTimeSwitchProxy = Date.now();
            }
        }

        const launch = dedup(async function (logger) {
            if (identities && !identity) {
                await getIdentity({
                    lock: lockIdentityUntilLoaded,
                    ifAbsent: createIdentityFn && (async () => {
                        const _id = uuid4();
                        const {id, ...data} = await createIdentityFn.call(logger, getReqWithoutIdentities(_id));
                        const identity = {id: id || _id, data};
                        logger.info('New identity for request is created: ', identity.id, ' ', identity.data);
                        return identity;
                    }),
                    waitForStore: !createIdentityFn
                });
            }
            if (proxies) {
                const identityId = identity && identity.id || defaultIdentityId;
                if (!proxy || identityId) {
                    await getProxy(identityId);
                }
            }
        }, {key: null});

        req = async function (req, logger, _options) {
            logger = logger || this;

            const now = Date.now();
            if (identity && counter % switchIdentityEvery === 0) {
                logger.info(
                    'Request has been made ', counter, ' times and identity ',
                    identity.id, ' will be switched before next request.'
                );
                identity = undefined;
            }
            if (identity && now - lastTimeSwitchIdentity > switchIdentityAfter * 1000) {
                logger.info(
                    'Request has been using identity ', identity.id, ' since ', new Date(lastTimeSwitchIdentity),
                    ' which will be switched before next request.'
                );
                identity = undefined;
            }
            if (proxy && counter % switchProxyEvery === 0) {
                logger.info(
                    'Request has been made ', counter, ' times and proxy ',
                    proxy, ' will be switched before next request.'
                );
                proxy = undefined;
            }
            if (proxy && now - lastTimeSwitchProxy > switchProxyAfter * 1000) {
                logger.info(
                    'Request has been using proxy ', proxy, ' since ', new Date(lastTimeSwitchProxy),
                    ' which will be switched before next request.'
                );
                proxy = undefined;
            }

            _options = {...defaults, ..._options};
            if (typeof _options.jar === 'boolean' && _options.jar) {
                _options = {..._options, jar};
            }
            let trial = 0, options = _options;
            while (true) {
                trial++;
                if (identities && !identity || proxies && !proxy) {
                    await launch(logger);
                }
                if (identity || proxy) {
                    options = cloneDeep(_options);
                }
                if (identity) {
                    try {
                        const loaded = await loadIdentityFn.call(
                            logger, options, identity.data,
                            {request: getReqWithoutIdentities(identity.id)}
                        );
                        if (loaded) {
                            identities.update(identity, loaded);
                        }
                        if (proxies) {
                            await getProxy(identity.id);
                        }
                        identities.touch(identity);
                        identities.unlock(identity);
                    } catch (e) {
                        identities.unlock(identity);
                        if (loadIdentityError) {
                            const message = await loadIdentityError.call(logger, e, options, identity.data);
                            if (message) {
                                const logMessages = Array.isArray(message) ? message : [message];
                                logger.warn(
                                    'Loading identity failed with ',
                                    proxy || 'no proxy', ' / ', identity.id || 'no identity',
                                    ' during request trial ', trial, '/', maxRetryIdentities, ': ', ...logMessages
                                );
                                if (identities) identities.deprecate(identity);
                                identity = undefined;
                                if (switchProxyOnInvalidIdentity) {
                                    proxy = undefined;
                                }
                                if (trial <= maxRetryIdentities) {
                                    continue;
                                } else {
                                    logger.fail('_request_load_identity_failed', ...logMessages);
                                }
                            }
                        }
                        throw e;
                    }
                }
                if (proxy) {
                    options.proxy = `http://${proxy}`;
                    proxies.touch(proxy);
                }
                let response, error, proxyInvalidMessage, identityInvalidMessage;
                try {
                    response = await req(logger, options);
                    if (debug) {
                        logger.debug('request(', options, ') ', proxy || 'no proxy', ' / ', identity && identity.id || 'no identity', ' -> resp');
                    }
                } catch (e) {
                    error = e;
                    response = error.response;
                    if (!options.resolveWithFullResponse) {
                        response = response && response.body;
                    }
                    if (debug) {
                        logger.debug('request(', options, ') ', proxy || 'no proxy', ' / ', identity && identity.id || 'no identity', ' -> error');
                    }
                }
                const processed = await processReturnedFn.call(logger, options, {
                    identities,
                    identityId: (identity || {}).id,
                    identity: (identity || {}).data,
                    proxies,
                    proxy,
                    response,
                    error
                });
                if (processed) {
                    response = processed.response || response;
                    error = processed.error || error;
                }
                if (identity) {
                    const updated = await updateIdentityFn.call(
                        logger, options, {
                            identities,
                            identityId: identity.id,
                            identity: identity.data,
                            proxies,
                            proxy,
                            response,
                            error
                        }
                    );
                    if (updated) {
                        identities.update(identity, updated);
                    }
                }
                if (proxy) {
                    proxyInvalidMessage = await validateProxyFn.call(
                        logger, options, {
                            identities,
                            identityId: (identity || {}).id,
                            identity: (identity || {}).data,
                            proxies,
                            proxy,
                            response,
                            error
                        }
                    );
                }
                if (identity) {
                    identityInvalidMessage = await validateIdentityFn.call(
                        logger, options, {
                            identities,
                            identityId: identity.id,
                            identity: identity.data,
                            proxies,
                            proxy,
                            response,
                            error
                        }
                    );
                }

                if (proxyInvalidMessage || identityInvalidMessage) {
                    const logMessages = ['request(', options, ') ->'];
                    if (proxyInvalidMessage) logMessages.push(
                        ' [Proxy Invalid] ',
                        ...(Array.isArray(proxyInvalidMessage) ? proxyInvalidMessage : [proxyInvalidMessage])
                    );
                    if (identityInvalidMessage) logMessages.push(
                        ' [Identity Invalid] ',
                        ...(Array.isArray(identityInvalidMessage) ? identityInvalidMessage : [identityInvalidMessage])
                    );
                    if (trial <= maxRetryIdentities) {
                        logger.warn(
                            'Request failed with ', proxy || 'no proxy', ' / ', identity && identity.id || 'no identity',
                            ', will rotate and re-try (', trial, '/', maxRetryIdentities, '): ', ...logMessages
                        );
                    } else {
                        logger.warn(
                            'Request failed with ', proxy || 'no proxy', ' / ', identity && identity.id || 'no identity',
                            ' and too many rotations have been tried (',
                            maxRetryIdentities, '/', maxRetryIdentities, '): ', ...logMessages
                        );
                    }

                    if (proxyInvalidMessage && proxies) {
                        proxies.deprecate(proxy);
                        proxy = undefined;
                        if (switchIdentityOnInvalidProxy) identity = undefined;
                    }
                    if (identityInvalidMessage && identities) {
                        identities.deprecate(identity);
                        identity = undefined;
                        if (switchProxyOnInvalidIdentity) proxy = undefined;
                    }

                    if (trial <= maxRetryIdentities) {
                        continue;
                    } else {
                        logger.fail('_request_failed', ...logMessages);
                    }
                }
                if (error) {
                    throw error;
                }

                counter++;

                if (identity) {
                    identities.renew(identity);
                }
                return response;
            }
        }.bind(this, req);

        return Object.assign(req, extra);

    }
};
