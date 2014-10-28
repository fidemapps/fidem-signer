var crypto = require('./util/crypto');
var dateUtil = require('./util/date');
var pathUtil = require('./util/path');
var headersUtil = require('./util/headers');

/**
 * Verify a signature.
 *
 * @param {object} request
 * @param {object} credentials
 * @param {object} parameters
 * @returns {boolean}
 */

exports.verify = function (request, credentials, parameters) {
  return exports.generate(request, credentials, parameters) === parameters.Signature;
};

/**
 * Generate a signature.
 *
 * @param {object} request
 * @param {object} credentials
 * @param {object} parameters
 * @returns {string}
 */

exports.generate = function (request, credentials, parameters) {
  var headers = headersUtil.normalize(request.headers);
  var fidemDateTime = headers['x-fidem-date'];

  var fidemDate = dateUtil.stripTime(fidemDateTime);

  var key = crypto.hmac('FIDEM' + credentials.secretAccessKey, fidemDate);
  var pathParts = pathUtil.parse(request.path);

  headers = headersUtil.filter(headers, parameters.SignedHeaders);

  var body = request.body || '';
  if (typeof body !== 'string') {
    body = JSON.stringify(request.body);
  }

  var canonicalString = [
    request.method || 'GET',
    pathParts[0] || '/',
    pathParts[1] || '',
    headersUtil.serialize(headers) + '\n',
    parameters.SignedHeaders,
    crypto.hash(body, 'hex')
  ].join('\n');

  var plain = [
    parameters.scheme,
    fidemDateTime,
    credentials.accessKeyId + '/' + fidemDate + '/fidem',
    crypto.hash(canonicalString, 'hex')
  ].join('\n');

  return crypto.hmac(key, plain, 'hex');
};
