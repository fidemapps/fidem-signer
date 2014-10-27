/**
 * Normalize request to prevent bugs.
 *
 * @param {object} request
 * @returns {object}
 */

exports.normalize = function (request) {
  request.headers = request.headers || {};
  return request;
};
