/**
 * Convert date in ISO datetime.
 *
 * @param {string} date
 * @returns {string}
 */

exports.toISODateTime = function (date) {
  date = new Date(date || new Date());
  return date.toISOString().replace(/[:\-]|\.\d{3}/g, '');
};

/**
 * Convert date in ISO date.
 *
 * @param {string} date
 * @returns {string}
 */

exports.stripTime = function (date) {
  return date.substr(0, 8);
};
