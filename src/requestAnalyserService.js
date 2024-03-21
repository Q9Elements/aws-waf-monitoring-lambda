const constants = require('./constants');

/**
 * This function checks if the specific request contains payload that can be used to exploit
 * XSS vulnerability.
 * @param {*} requestItem - request that should be inspected
 * @returns result of inspection
 */
function checkForXSSInjectionAttackAttempt(requestItem) {
    console.debug('[request-analyser-service] Inspecting request to detect injection attack queries...');
    return requestItem.ruleId.includes('XSSRule');
}

/**
 * This function checks if the specific request contains payload that can be used to exploit
 * SQL injection vulnerability.
 * @param {*} requestItem - request that should be inspected
 * @returns result of inspection
 */
function checkForSQLInjectionAttackAttempt(requestItem) {
    console.debug('[request-analyser-service] Inspecting request to detect injection attack queries...');
    return requestItem.ruleId.includes('SqlInjectionRule');
}

/**
 * This function analyses provided request in order to determine if it contains malicious payloads.
 * Results of analysis are added as additional fields to the original item.
 * @param {*} requestItem - request that should be analysed
 * @returns analysis results
 */
function analyseCapturedRequest(requestItem) {
    console.log('[request-analyser-service] Analysing captured request for malicious payloads...');
    const analysisResults = [
        { result: checkForXSSInjectionAttackAttempt(requestItem), reason: constants.REASONS_FOR_BLACKLISTING_IP.XSS },
        { result: checkForSQLInjectionAttackAttempt(requestItem), reason: constants.REASONS_FOR_BLACKLISTING_IP.SQLI },
    ];
    [requestItem.isRequestMalicious, requestItem.reasonsForBlacklisting] = [false, []];

    for (const item of analysisResults) {
        if (item.result) {
            requestItem.isRequestMalicious = true;
            requestItem.reasonsForBlacklisting.push(item.reason);
        }
    }

    return requestItem;
}

module.exports = {
    analyseCapturedRequest,
};
