'use strict';

var fidemVerifier = exports,
    crypto = require('crypto'),
    moment = require('moment'),
    _ = require('lodash'),
    lru = require('lru-cache'),
    credentialsCache = lru(1000);

/////////////////////////////////////////////////////////////////////////////////
// Inspiration and documentation
//
// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
// https://github.com/mhart/aws4
//

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
function RequestVerifier(request, credentials, authParamaters) {

    this.request = request;
    this.credentials = credentials;

    this.service = authParamaters.credentialArray[2];
    this.region = authParamaters.credentialArray[3];

    this.SignedHeaders = authParamaters.SignedHeaders;
    this.signedHeadersArray = authParamaters.signedHeadersArray;

    this.datetime = this.request.get('X-Fidem-Date');
    this.date = this.datetime.replace(/[:\-]|\.\d{3}/g, '').substr(0, 8);
}

RequestVerifier.prototype.signature = function () {
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

RequestVerifier.prototype.stringToSign = function () {
    return [
        'FIDEM4-HMAC-SHA256',
        this.datetime,
        this.credentialString(),
        hash(this.canonicalString(), 'hex')
    ].join('\n');
};

RequestVerifier.prototype.canonicalString = function () {
    var pathParts = (this.request.path || '/').split('?', 2);
    return [
        this.request.method,
            pathParts[0] || '/',
            pathParts[1] || '',
            this.canonicalHeaders() + '\n',
        this.SignedHeaders,
        hash(this.request.body ? JSON.stringify(this.request.body) : '', 'hex')
    ].join('\n');
};


RequestVerifier.prototype.canonicalHeaders = function () {
    var headers = {};
    var _this = this;
    _.forEach(this.signedHeadersArray, function (key) {
        headers[key] = _this.request.headers[key];
    });

    function trimAll(header) {
        if (!header) {
            return header;
        }

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


RequestVerifier.prototype.credentialString = function () {
    return [
        this.date,
        this.region,
        this.service,
        'fidem4_request'
    ].join('/');
};


fidemVerifier.RequestVerifier = RequestVerifier;

fidemVerifier.parseAuthorizationHeader = function (request) {
    var authHeader = request.get('Authorization');
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

fidemVerifier.validateDate = function (req, authParamaters) {
    var fidemDateHeader = req.get('X-Fidem-Date');

    if (!fidemDateHeader) {
        return false;
    }

    if (fidemDateHeader.replace(/[:\-]|\.\d{3}/g, '').substr(0, 8) !== authParamaters.credentialArray[1]) {
        return false;
    }

    var fidemDate = moment(fidemDateHeader, moment.ISO_8601);
    var ms = moment().diff(fidemDate);
    var d = moment.duration(ms);

    return d.as('minutes') < 15;
};

fidemVerifier.validateSignature = function (req, credentials, authParamaters) {
    if (!authParamaters) {
        authParamaters = this.parseAuthorizationHeader(req);
    }

    var signature = new RequestVerifier(req, credentials, authParamaters).signature();
    return signature === authParamaters.Signature;
};
