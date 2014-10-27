var crypto = require('crypto');

/**
 * Crypt using hmac.
 *
 * @param {string} key
 * @param {string} string
 * @param {string} encoding
 * @returns {string}
 */

exports.hmac = function (key, string, encoding) {
  return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding);
};

/**
 * Hash using hmac.
 *
 * @param {string} key
 * @param {string} string
 * @param {string} encoding
 * @returns {string}
 */

exports.hash = function (string, encoding) {
  return crypto.createHash('sha256').update(string, 'utf8').digest(encoding);
};
