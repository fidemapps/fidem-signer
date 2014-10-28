/**
 * Parse path.
 *
 * @param {string} path
 */

exports.parse = function (path) {
  return (path || '/').split('?', 2);
};
