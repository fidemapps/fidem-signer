'use strict';

var dateUtil = require('./util/date');
var requestUtil = require('./util/request');
var authHeader = require('./auth-header');
var signature = require('./signature');

/**
 * Verify a request.
 *
 * @param {object} request
 * @param {object} credentials
 * @returns {boolean}
 */

exports.verify = function (request, credentials) {
  request = requestUtil.normalize(request);

  // Parse auth header.
  var parameters = authHeader.parse(request);
  if (!parameters) return false;

  return signature.verify(request, credentials, parameters);
};

/**
 * Sign a request.
 *
 * @param {object} request
 * @param {object} credentials
 * @returns {object}
 */

exports.sign = function (request, credentials) {
  request = requestUtil.normalize(request);
  request.headers['X-Fidem-Date'] = dateUtil.toISODateTime(
    request.headers.Date || request.headers.date
  );
  request.headers.Authorization = authHeader.format(request, credentials);
  return request;
};
