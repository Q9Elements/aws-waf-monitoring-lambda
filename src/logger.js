/* eslint-disable prefer-rest-params */
const constants = require('./constants');

/**
 * Set up logger. Currently, the solution uses simple console.log or console.debug
 * but in case of need you can integrate another logger instead.
 */
function setUpLogger() {
    if (constants.LOG_LEVEL === 'debug')
        console.debug = function() {
            console.log.apply(this, arguments);
        };
    else
        console.debug = function() {};
}

module.exports = {
    setUpLogger,
};
