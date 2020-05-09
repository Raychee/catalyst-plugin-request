const request = require('request-promise-native');
const uuid4 = require('uuid/v4');
const {memoize, cloneDeep, isPlainObject} = require('lodash');

const {dedup, timeout: withTimeout, shrink} = require('@raychee/utils');


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

function defaultUpdateIdentityFn(options, {identity, response}) {
    if (identity && identity.cookies) {
        if (options.resolveWithFullResponse) {
            const setCookie = response && response.headers['set-cookie'];
            if (setCookie && setCookie.length > 0) {
                const cookies = setCookie.map(c => {
                    const [[key, value], ...props] = c.split('; ').map(f => f.split('='));
                    const cookie = {key, value};
                    for (const [p, v] of props) {
                        switch (p) {
                            case 'Path':
                                cookie.path = v;
                                break;
                            case 'Domain':
                                cookie.domain = v;
                                break;
                            case 'Expires':
                                cookie.expires = v;
                                break;
                        }
                    }
                    return cookie;
                });
                return {...identity, cookies};
            }
        } else if (options.jar) {
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
            lockIdentityInUse = false,
            processReturnedFn = defaultProcessReturnedFn,
        } = {},
        {pluginLoader}
    ) {

        let _req = request, jar = request.jar(), extra = {};
        defaults = timeout > 0 ? {timeout: timeout * 1000, ...defaults} : defaults;

        if (timeout > 0) {
            _req = withTimeout(_req, timeout * 1000, {
                error() {
                    const e = new Error('ETIMEDOUT');
                    e.code = 'ETIMEDOUT';
                    e.connect = true;
                    return e;
                }
            });
        }

        let req = async function (logger, options) {
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

        if (isPlainObject(identities)) {
            const plugin = await pluginLoader.get({type: 'identities', ...identities});
            identities = plugin.instance;
        }
        if (isPlainObject(proxies)) {
            const plugin = await pluginLoader.get({type: 'proxies', ...proxies});
            proxies = plugin.instance;
        }
        if (identities) extra.identities = identities;
        if (proxies) extra.proxies = proxies;
        let identity = undefined, proxy = undefined;
        let counter = 0, lastTimeSwitchIdentity = undefined, lastTimeSwitchProxy = undefined;
        extra.currentIdentity = () => identity;
        extra.currentProxy = () => proxy;
        extra.setCurrentIdentity = (newIdentity) => identity = newIdentity;
        extra.setCurrentProxy = (newProxy) => proxy = newProxy;
        extra.clearIdentity = clearIdentity;

        const getReqWithoutIdentities = memoize(defaultIdentityId => {
            let plugin = undefined;
            return {
                async instance(...args) {
                    if (!plugin) {
                        plugin = await pluginLoader.get({
                            type: 'request',
                            defaults, smartError, timeout, debug, proxies,
                            maxRetryIdentities, switchProxyEvery, switchProxyAfter,
                            validateProxyFn, defaultIdentityId
                        });
                    }
                    return await plugin.instance(...args);
                },
                destroy() {
                    if (plugin && plugin.destroy) {
                        return plugin.destroy();
                    }
                },
            };
        });

        async function getIdentity(...args) {
            const old = identity;
            identity = await identities.get(...args);
            if ((old && old.id) !== (identity && identity.id)) {
                lastTimeSwitchIdentity = Date.now();
            }
        }

        function clearIdentity() {
            if (identity && identities && lockIdentityInUse) {
                identities.unlock(identity);
                identity = undefined;
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
                    lock: lockIdentityUntilLoaded || lockIdentityInUse,
                    ifAbsent: createIdentityFn && (async () => {
                        const _id = uuid4();
                        const {instance, destroy} = getReqWithoutIdentities(_id);
                        try {
                            const {id, ...data} = await createIdentityFn.call(logger, instance);
                            const identity = {id: id || _id, data};
                            logger.info('New identity for request is created: ', identity.id, ' ', identity.data);
                            return identity;
                        } finally {
                            await destroy();
                        }
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
                    const reqWithoutIdentities = getReqWithoutIdentities(identity.id);
                    try {
                        const loaded = await loadIdentityFn.call(
                            logger, options, identity.data,
                            {request: reqWithoutIdentities.instance}
                        );
                        if (loaded && identities) {
                            identities.update(identity, loaded);
                        }
                        if (proxies) {
                            await getProxy(identity.id);
                        }
                        if (identities) identities.touch(identity);
                    } catch (e) {
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
                                clearIdentity();
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
                    } finally {
                        await reqWithoutIdentities.destroy();
                        if (identities && lockIdentityUntilLoaded && !lockIdentityInUse) {
                            identities.unlock(identity);
                        }
                    }
                }
                if (proxy && proxies) {
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
                    if (updated && identities) {
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
                        if (switchIdentityOnInvalidProxy) clearIdentity();
                    }
                    if (identityInvalidMessage && identities) {
                        identities.deprecate(identity);
                        clearIdentity();
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

                if (identity && identities) {
                    identities.renew(identity);
                }

                counter++;
                const now = Date.now();
                if (identity && counter % switchIdentityEvery === 0) {
                    logger.info(
                        'Request has been made ', counter, ' times and identity ',
                        identity.id, ' will be switched before next request.'
                    );
                    clearIdentity();
                }
                if (identity && now - lastTimeSwitchIdentity > switchIdentityAfter * 1000) {
                    logger.info(
                        'Request has been using identity ', identity.id, ' since ', new Date(lastTimeSwitchIdentity),
                        ' which will be switched before next request.'
                    );
                    clearIdentity();
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

                return response;
            }
        }.bind(this, req);

        return Object.assign(req, extra);

    },
    async destroy(req) {
        return req.clearIdentity();
    }
};
