/**
 * Serialize keys of the header.
 *
 * @param {object} headers
 * @returns {string}
 */

exports.serializeKeys = function (headers) {
  headers = headers || {};

  return Object.keys(headers)
    .map(function (key) {
      return key.toLowerCase();
    })
    .sort()
    .join(';');
};

/**
 * Serialize complete headers.
 *
 * @param {object} headers
 * @returns {string}
 */

exports.serialize = function (headers) {
  return Object.keys(headers)
    .sort(function (a, b) {
      return a < b ? -1 : 1;
    })
    .map(function (key) {
      return key + ':' + headers[key];
    })
    .join('\n');
};

/**
 * Filter headers.
 *
 * @param {object} headers
 * @param {string} query
 * @returns {object}
 */

exports.filter = function (headers, query) {
  query = query.split(';');

  return query.reduce(function (filtered, key) {
    filtered[key] = headers[key];
    return filtered;
  }, {});
};

/**
 * Lowercaseify all headers.
 *
 * @param {object} headers
 * @returns {object}
 */

exports.normalize = function (headers) {
  headers = headers || {};

  function trimAll(header) {
    return (header + '').trim().replace(/\s+/g, ' ');
  }

  var trimed = {};

  Object.keys(headers).forEach(function (key) {
    trimed[key.toLowerCase()] = trimAll(headers[key]);
  });

  return trimed;
};
