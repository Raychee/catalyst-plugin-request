const request = require('request-promise-native');
const {v4: uuid4} = require('uuid');
const {memoize, cloneDeep, isPlainObject, isEmpty} = require('lodash');

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
    key({smartError = true, timeout = 0, debug = false, type, ...rest}) {
        if (!isEmpty(rest)) return;
        return {smartError, timeout, debug};
    },
    async create(
        {
            defaults, smartError = true, timeout = 0, debug = false,
            identities: identitiesOptions, proxies: proxiesOptions,
            maxRetryIdentities = 10,
            switchIdentityEvery, switchProxyEvery,
            switchIdentityAfter, switchProxyAfter,
            switchIdentityOnInvalidProxy = false, switchProxyOnInvalidIdentity = true,
            createIdentityFn,
            createIdentityError,
            loadIdentityFn = defaultLoadIdentityFn,
            updateIdentityFn = defaultUpdateIdentityFn,
            validateIdentityFn = defaultValidateIdentityFn,
            validateProxyFn = defaultValidateProxyFn,
            defaultIdentityId,
            loadIdentityError,
            lockIdentityUntilLoaded = false,
            lockIdentityInUse = false,
            processReturnedFn = defaultProcessReturnedFn,
        },
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

        if (createIdentityFn) {
            identitiesOptions = {
                async createIdentityFn() {
                    const _id = uuid4();
                    const {bound, destroy} = getReqWithoutIdentities(_id);
                    try {
                        const {id, ...data} = await createIdentityFn.call(this, bound);
                        return {id: id || _id, data};
                    } finally {
                        await destroy();
                    }
                },
                createIdentityError,
                ...identitiesOptions
            };
        }

        const identities = identitiesOptions && await pluginLoader.get({type: 'identities', ...identitiesOptions});
        const proxies = proxiesOptions && await pluginLoader.get({type: 'proxies', ...proxiesOptions});
        if (identities) extra.identities = identities.bound;
        if (proxies) extra.proxies = proxies.bound;
        let identity = undefined, proxy = undefined;
        let counter = 0, lastTimeSwitchIdentity = undefined, lastTimeSwitchProxy = undefined;
        extra.currentIdentity = () => identity;
        extra.currentProxy = () => proxy;
        extra.setCurrentIdentity = (newIdentity) => identity = newIdentity;
        extra.setCurrentProxy = (newProxy) => proxy = newProxy;
        extra.clearIdentity = clearIdentity;
        extra._unload = async (job) => {
            if (identities) {
                await identities.unload(job);
            }
            if (proxies) {
                await proxies.unload(job);
            }
        };
        extra._destroy = async () => {
            clearIdentity();
            if (identities) {
                await identities.destroy();
            }
            if (proxies) {
                await proxies.destroy();
            }
        }

        const getReqWithoutIdentities = memoize(defaultIdentityId => {
            let plugin = undefined;
            return {
                async bound(...args) {
                    if (!plugin) {
                        plugin = await pluginLoader.get({
                            type: 'request',
                            defaults, smartError, timeout, debug, proxies: proxiesOptions,
                            maxRetryIdentities, switchProxyEvery, switchProxyAfter,
                            validateProxyFn, defaultIdentityId
                        });
                    }
                    return plugin.bound(...args);
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
            identity = await identities.bound.get(...args);
            if ((old && old.id) !== (identity && identity.id)) {
                lastTimeSwitchIdentity = Date.now();
            }
        }

        function clearIdentity() {
            if (identity && identities && lockIdentityInUse) {
                identities.bound.unlock(identity);
                identity = undefined;
            }
        }

        async function getProxy(...args) {
            const old = proxy;
            proxy = await proxies.bound.get(...args);
            if (old !== proxy) {
                lastTimeSwitchProxy = Date.now();
            }
        }

        const launch = dedup(async function () {
            if (identities && !identity) {
                await getIdentity({lock: lockIdentityUntilLoaded || lockIdentityInUse});
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
                    await launch();
                }
                if (identity || proxy) {
                    options = cloneDeep(_options);
                }
                if (identity) {
                    const reqWithoutIdentities = getReqWithoutIdentities(identity.id);
                    try {
                        const loaded = await loadIdentityFn.call(
                            logger, options, identity.data,
                            {
                                request: reqWithoutIdentities.bound, identities: identities && identities.bound,
                                identity, identityId: identity.id
                            }
                        );
                        if (loaded && identities) {
                            identities.bound.update(identity, loaded);
                        }
                        if (proxies) {
                            await getProxy(identity.id);
                        }
                        if (identities) identities.bound.touch(identity);
                    } catch (e) {
                        if (loadIdentityError) {
                            const message = await loadIdentityError.call(
                                logger, e, options, identity.data,
                                {identities: identities && identities.bound, identity, identityId: identity.id}
                            );
                            if (message) {
                                const logMessages = Array.isArray(message) ? message : [message];
                                logger.warn(
                                    'Loading identity failed with ',
                                    proxy || 'no proxy', ' / ', identity.id || 'no identity',
                                    ' during request trial ', trial, '/', maxRetryIdentities, ': ', ...logMessages
                                );
                                if (identities) identities.bound.deprecate(identity);
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
                            identities.bound.unlock(identity);
                        }
                    }
                }
                if (proxy && proxies) {
                    options.proxy = `http://${proxy}`;
                    proxies.bound.touch(proxy);
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
                    identities: identities && identities.bound,
                    identityId: (identity || {}).id,
                    identity: (identity || {}).data,
                    proxies: proxies && proxies.bound,
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
                            identities: identities && identities.bound,
                            identityId: identity.id,
                            identity: identity.data,
                            proxies: proxies && proxies.bound,
                            proxy,
                            response,
                            error
                        }
                    );
                    if (updated && identities) {
                        identities.bound.update(identity, updated);
                    }
                }
                if (proxy) {
                    proxyInvalidMessage = await validateProxyFn.call(
                        logger, options, {
                            identities: identities && identities.bound,
                            identityId: (identity || {}).id,
                            identity: (identity || {}).data,
                            proxies: proxies && proxies.bound,
                            proxy,
                            response,
                            error
                        }
                    );
                }
                if (identity) {
                    identityInvalidMessage = await validateIdentityFn.call(
                        logger, options, {
                            identities: identities && identities.bound,
                            identityId: identity.id,
                            identity: identity.data,
                            proxies: proxies && proxies.bound,
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
                        proxies.bound.deprecate(proxy);
                        proxy = undefined;
                        if (switchIdentityOnInvalidProxy) clearIdentity();
                    }
                    if (identityInvalidMessage && identities) {
                        identities.bound.deprecate(identity);
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
                    identities.bound.renew(identity);
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

        return Object.assign(req, extra);

    },
    async unload(req, job) {
        await req._unload(job);
    },
    async destroy(req) {
        await req._destroy();
    }
};
