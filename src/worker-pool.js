const _ = require('lodash');
const utils = require('./utils');
const requestAnalyser = require('./requestAnalyserService');

/**
 * This function transforms the original log record and inserts only
 * the most important from the investigators' perspective data.
 * NOTE: If you're are going to change format of the output request,
 * please add appropriate changes to notificationService.js
 * @param {*} loggedRequest - logged by AWS WAF request
 * @returns formatted log record with a predefined structure
 * @todo Consider adding timestamp to the output records
 */
function formatLogRecord(loggedRequest) {
    console.log('[logRecordsProcessor|worker-pool] Formatting log record...');
    let fullRequestUrl = `${loggedRequest.httpRequest.httpMethod} `
        + utils.sanitizeLinks(loggedRequest.httpRequest.uri);
    if (loggedRequest.httpRequest.args !== '')
        fullRequestUrl += `?${utils.sanitizeLinks(loggedRequest.httpRequest.args)}`;
    let matchDetails = '';
    const isMatchDetailsPresent = loggedRequest.terminatingRuleMatchDetails && loggedRequest.terminatingRuleMatchDetails !== null
        && loggedRequest.terminatingRuleMatchDetails.length > 0;
    if (isMatchDetailsPresent)
        try {
            matchDetails = loggedRequest.terminatingRuleMatchDetails.map((el) => {
                return `${el.conditionType}::${el.location}::[Matched payload]::`
                    + (el.matchedData.map((item) => utils.sanitizeLinks(item)).join(' ') || '');
            }).join('\n');
        } catch (err) { matchDetails = ''; }
    return {
        ruleId: loggedRequest.terminatingRuleId,
        action: loggedRequest.action,
        srcIpDetails: {
            ip: loggedRequest.httpRequest.clientIp,
            country: loggedRequest.httpRequest.country,
            abuseIpDBInfo: `https://www.abuseipdb.com/check/${loggedRequest.httpRequest.clientIp}`,
            threatBookInfo: `https://threatbook.io/ip/${loggedRequest.httpRequest.clientIp}`,
            virusTotalInfo: `https://www.virustotal.com/gui/ip-address/${loggedRequest.httpRequest.clientIp}/detection`,
        },
        fullCapturedRequest: `${fullRequestUrl} ${loggedRequest.httpRequest.httpVersion}\n`
            + loggedRequest.httpRequest.headers.map((el) => {
                return `${el.name}: ${el.value}`;
            }).join('\n'),
        fullRequestUrl,
        matchDetails,
        nonTerminatingMatchingRules: loggedRequest.nonTerminatingMatchingRules || [],
        rateBasedRuleList: loggedRequest.rateBasedRuleList || [],
        timestamp: loggedRequest.timestamp,
    };
}

/**
 * Main aim of this function is to put a formatted rule into the right
 * findings list. This information is used later to create notifications for
 * the team
 * @param {Object} params Required params:
 * formattedLogRecord - formated log record with the predefined structure
 * findingsGroups - groups for findings, related to different AWS WAF rules
 * Please note: an up to date list of rule ids can be taken from AWS WAF
 * by using AWS Console
 */
function addFindingToDedicatedList({ formattedLogRecord, findingsGroups }) {
    console.log('[logRecordsProcessor|worker-pool] Adding formated log to a dedicated list...');
    switch (formattedLogRecord.ruleId) {
    case 'AWSWAFSecurityAutomationsIPReputationListsRule':
        findingsGroups.ipReputationRuleFindings.push(formattedLogRecord); break;
    case 'AWSWAFSecurityAutomationsSqlInjectionRule':
        findingsGroups.sqlInjectionFindings.push(formattedLogRecord); break;
    case 'AWSWAFSecurityAutomationsXSSRule':
        findingsGroups.xssFindings.push(formattedLogRecord); break;
    case 'AWSWAFSecurityAutomationsScannersAndProbesRule':
        findingsGroups.scannersAndProbesFindings.push(formattedLogRecord); break;
    case 'AWSWAFSecurityAutomationsBlacklistRule':
        findingsGroups.blackListRuleFindings.push(formattedLogRecord); break;
    // eslint-disable-next-line no-empty
    default: {}
    }
}

/**
 * This function processes log records and extracts valuable information
 * @param {Object} params Required params:
 * logRecords - list of extracted from the file requets
 * findingsGroups - groups for findings, related to different AWS WAF rules
 */
function processAWSWAFFindings({ logRecords, findingsGroups }) {
    console.log('[logRecordsProcessor|worker-pool] Processing AWS WAF log records...');
    let jsonData, formattedLogRecord, analysedRecord;

    for (const logRecord of logRecords) {
        jsonData = JSON.parse(logRecord);
        formattedLogRecord = formatLogRecord(jsonData);
        if (formattedLogRecord.ruleId === 'Default_Action')
            for (const rule of formattedLogRecord.nonTerminatingMatchingRules) {
                analysedRecord = requestAnalyser
                    .analyseCapturedRequest(_.merge(formattedLogRecord, { ruleId: rule.ruleId, action: rule.action }));
                addFindingToDedicatedList({
                    formattedLogRecord: analysedRecord,
                    findingsGroups,
                });
            }
        else {
            analysedRecord = requestAnalyser.analyseCapturedRequest(formattedLogRecord);
            addFindingToDedicatedList({ formattedLogRecord: analysedRecord, findingsGroups });
        }
    }
}

module.exports = async(logRecords) => {
    const findingsGroups = utils.generateGroupsForDetectedIssues();
    processAWSWAFFindings({ logRecords, findingsGroups });
    return findingsGroups;
};
