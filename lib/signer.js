'use strict';

/////////////////////////////////////////////////////////////////////////////////
// Inspiration and documentation
//
// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
// https://github.com/mhart/aws4
//

var fidemSigner = exports,
    url = require('url'),
    crypto = require('crypto'),
    lru = require('lru-cache'),
    credentialsCache = lru(1000);

function Param(string) {
    var SEPARATOR = /(?: |,)/g;
    var OPERATOR = /=/;
    if (string && SEPARATOR.test(string) && OPERATOR.test(string)) {
        string.split(SEPARATOR).forEach(function (param, idx) {
            var parts = param.split(OPERATOR).map(function (part) {
                return part.trim();
            });
            if (parts.length === 2) {
                /* jshint ignore:start */
                this[parts[0]] || (this[parts[0]] = {});
                /* jshint ignore:end */
                this[parts[0]] = parts[1];
            }
        }, this);
    }
    return this;
}

function parseHttpHeader(string) {
    Param.prototype.toString = function toString() {
        return string;
    };

    return new Param(string);
}

function hmac(key, string, encoding) {
    return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding);
}

function hash(string, encoding) {
    return crypto.createHash('sha256').update(string, 'utf8').digest(encoding);
}

// request: { path | body, [host], [method], [headers], [service], [region] }
// credentials: { accessKeyId, secretAccessKey, [sessionToken] }
function RequestSigner(request, credentials) {

    if (typeof request === 'string') {
        request = url.parse(request);
    }

    this.request = request;
    this.credentials = credentials || this.defaultCredentials();

    this.service = request.service || '';
    this.region = request.region || '';
}

RequestSigner.prototype.sign = function () {
    var request = this.request;
    var headers = request.headers || {};
    var date = new Date(headers.Date || new Date());

    this.datetime = date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
    this.date = this.datetime.substr(0, 8);

    if (!request.method && request.body)
        request.method = 'POST';

    if (!headers.Host && !headers.host)
        headers.Host = request.hostname || request.host;
    if (!request.hostname && !request.host)
        request.hostname = headers.Host || headers.host;

    if (request.body && !headers['Content-Type'] && !headers['content-type'])
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';

    if (request.body && !headers['Content-Length'] && !headers['content-length'])
        headers['Content-Length'] = Buffer.byteLength(request.body);

    headers['X-Fidem-Date'] = this.datetime;

    if (this.credentials.sessionToken) {
        headers['X-Fidem-Security-Token'] = this.credentials.sessionToken;
    }

    if (headers.Authorization) {
        delete headers.Authorization;
    }
    headers.Authorization = this.authHeader();

    return request;
};

RequestSigner.prototype.generateSignature = function () {
    var request = this.request;
    var headers = request.headers || {};
    var date = new Date(headers.Date || new Date());

    this.datetime = date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
    this.date = this.datetime.substr(0, 8);

    if (!request.method && request.body)
        request.method = 'POST';

    if (!headers.Host && !headers.host)
        headers.Host = request.hostname || request.host;
    if (!request.hostname && !request.host)
        request.hostname = headers.Host || headers.host;

    if (request.body && !headers['Content-Type'] && !headers['content-type'])
        headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';

    if (request.body && !headers['Content-Length'] && !headers['content-length'])
        headers['Content-Length'] = Buffer.byteLength(request.body);

    headers['X-Fidem-Date'] = this.datetime;

    if (this.credentials.sessionToken) {
        headers['X-Fidem-Security-Token'] = this.credentials.sessionToken;
    }

    if (headers.Authorization) {
        delete headers.Authorization;
    }

    return this.signature();
};

RequestSigner.prototype.authHeader = function () {
    return [
            'FIDEM4-HMAC-SHA256 Credential=' + this.credentials.accessKeyId + '/' + this.credentialString(),
            'SignedHeaders=' + this.signedHeaders(),
            'Signature=' + this.signature()
    ].join(', ');
};

RequestSigner.prototype.signature = function () {
    var cacheKey = [this.credentials.secretAccessKey, this.date, this.region, this.service].join(),
        kDate, kRegion, kService, kCredentials = credentialsCache.get(cacheKey);
    if (!kCredentials) {
        kDate = hmac('FIDEM4' + this.credentials.secretAccessKey, this.date);
        kRegion = hmac(kDate, this.region);
        kService = hmac(kRegion, this.service);
        kCredentials = hmac(kService, 'fidem4_request');
        credentialsCache.set(cacheKey, kCredentials);
    }
    return hmac(kCredentials, this.stringToSign(), 'hex');
};

RequestSigner.prototype.stringToSign = function () {
    return [
        'FIDEM4-HMAC-SHA256',
        this.datetime,
        this.credentialString(),
        hash(this.canonicalString(), 'hex')
    ].join('\n');
};

RequestSigner.prototype.canonicalString = function () {
    var pathParts = (this.request.path || '/').split('?', 2);
    return [
            this.request.method || 'GET',
            pathParts[0] || '/',
            pathParts[1] || '',
            this.canonicalHeaders() + '\n',
        this.signedHeaders(),
        hash(this.request.body || '', 'hex')
    ].join('\n');
};

RequestSigner.prototype.canonicalHeaders = function () {
    var headers = this.request.headers;

    function trimAll(header) {
        return header.toString().trim().replace(/\s+/g, ' ');
    }

    return Object.keys(headers)
        .sort(function (a, b) {
            return a.toLowerCase() < b.toLowerCase() ? -1 : 1;
        })
        .map(function (key) {
            return key.toLowerCase() + ':' + trimAll(headers[key]);
        })
        .join('\n');
};

RequestSigner.prototype.signedHeaders = function () {
    return Object.keys(this.request.headers)
        .map(function (key) {
            return key.toLowerCase();
        })
        .sort()
        .join(';');
};

RequestSigner.prototype.credentialString = function () {
    return [
        this.date,
        this.region,
        this.service,
        'fidem4_request'
    ].join('/');
};

RequestSigner.prototype.defaultCredentials = function () {
    // FIXME: (SG) I prefer to get theses values from options instead
    var env = process.env;
    return {
        accessKeyId: env.FIDEM_ACCESS_KEY_ID || env.FIDEM_ACCESS_KEY,
        secretAccessKey: env.FIDEM_SECRET_ACCESS_KEY || env.FIDEM_SECRET_KEY
    };
};

fidemSigner.RequestSigner = RequestSigner;

fidemSigner.sign = function (request, credentials) {
    return new RequestSigner(request, credentials).sign();
};

fidemSigner.generateSignature = function (request, credentials) {
    return new RequestSigner(request, credentials).generateSignature();
};

fidemSigner.parseAuthorizationHeader = function (request) {
    var authHeader = request.headers.Authorization;
    if (!authHeader) {
        throw new Error('No "Authorization" header found');
    }

    var index = authHeader.indexOf(' ');
    if (index === -1) {
        throw new Error('Missing authorization scheme and parameters');
    }

    var parameters = parseHttpHeader(authHeader.substr(index + 1));
    if (!parameters.Credential) {
        throw new Error('Missing "Credential" parameter');
    }
    if (!parameters.SignedHeaders) {
        throw new Error('Missing "SignedHeaders" parameter');
    }
    if (!parameters.Signature) {
        throw new Error('Missing "Signature" parameter');
    }

    parameters.scheme = authHeader.substr(0, index).trim();
    if (!parameters.scheme) {
        throw new Error('Missing Authorization scheme');
    }

    parameters.signedHeadersArray = parameters.SignedHeaders.split(';');
    parameters.credentialArray = parameters.Credential.split('/');

    return parameters;
};
