var signature = require('./signature');
var headersUtil = require('./util/headers');

/**
 * Parse authorization header and return parameters.
 *
 * @param {object} request
 * @returns {object}
 */

exports.parse = function (request) {
  var header = request.headers.Authorization || request.headers.authorization;

  if (!header) {
    return null;
  }

  var index = header.indexOf(' ');

  if (index === -1) {
    return null;
  }

  var parameters = extractParameters(header.substr(index + 1));

  if (!parameters.Credential) {
    return null;
  }

  if (!parameters.SignedHeaders) {
    return null;
  }

  if (!parameters.Signature) {
    return null;
  }

  parameters.scheme = header.substr(0, index).trim();

  if (!parameters.scheme) {
    return null;
  }

  return parameters;
};

/**
 * Extract parameters from header.
 *
 * @param {string} header
 * @returns {object}
 */

function extractParameters(header) {
  var SEPARATOR = /(?: |,)/g;
  var OPERATOR = /=/;

  return header.split(SEPARATOR).reduce(function (parameters, property) {
    var parts = property.split(OPERATOR).map(function (part) {
      return part.trim();
    });

    if (parts.length === 2)
      parameters[parts[0]] = parts[1];

    return parameters;
  }, {});
}

/**
 * Format auth header.
 *
 * @param {object} request
 * @param {object} credentials
 * @returns {string}
 */

exports.format = function (request, credentials) {
  var SignedHeaders = headersUtil.serializeKeys(request.headers);
  var scheme = 'FIDEM4-HMAC-SHA256';

  return [
    scheme + ' Credential=' + credentials.accessKeyId + '/fidem',
    'SignedHeaders=' + headersUtil.serializeKeys(request.headers),
    'Signature=' + signature.generate(request, credentials, {
      SignedHeaders: SignedHeaders,
      scheme: scheme
    })
  ].join(', ');
};
