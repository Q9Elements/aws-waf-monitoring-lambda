const _ = require('lodash');
const fs = require('node:fs');
const path = require('node:path');
const constants = require('./constants');
const utils = require('./utils');

/**
 * This function generates top IPs list by counting all captured by a rule request from one specific IP,
 * sorting them in a descending order and selecting top N (defined by _topItemsCount_ variable) items
 * from the final list.
 * @param {*} params - ruleFindingsList - findings for a selected rule, topItemsCount - number of items to return
 * from the final list, isForSlackMessage - return IPs in format that is used for Slack messages. Otherwise, it will
 * return a list of top IPs for a defined rule. We later write them to a file and use for generating daily analytics
 * @returns list of top IPs per rules defined based on the aforementioned criteria
 */
function getTopIPsListForRule({ ruleFindingsList, topItemsCount, isForSlackMessage } = {}) {
    console.log('[statisticsService] Determining a list of top IPs for a rule...');
    // Sample output: [['192.168.0.101', 6], ['10.11.0.1', 5]]
    const topIpsList = _.reverse(
        _.sortBy(
            _.toPairs(
                _.countBy(ruleFindingsList, function(el) { return el.srcIpDetails.ip; }),
            ),
            (el) => el[1]),
    ).slice(0, topItemsCount);

    return topIpsList.map((ipEl) => {
        const ipDetails = ruleFindingsList.find((el) => el.srcIpDetails.ip === ipEl[0]);
        if (isForSlackMessage)
            return `IP: ${ipEl[0]} :flag-${ipDetails.srcIpDetails.country.toLowerCase()}:;`
                + ` Captured requests: ${ipEl[1]}\n`
                + `<${ipDetails.srcIpDetails.abuseIpDBInfo}|AbuseIPDb> | `
                + `<${ipDetails.srcIpDetails.threatBookInfo}|Threat Book Info> | `
                + `<${ipDetails.srcIpDetails.virusTotalInfo}|VirusTotal>\n`;
        else
            return { [ipEl[0]]: ipDetails, requestsCount: ipEl[1] };
    });
}

/**
 * This function generates a list of IPs that are suggested to be included in blacklist because
 * they pose security risks for the application
 * @param {*} params - ruleFindingsList - findings for a selected rule, isForSlackMessage - return
 * IPs in format that is used for Slack messages. Otherwise, it will return a list of malicious
 * requests for a define rule. We later write them to a file and use for generating daily analytics
 * @returns list of IPs that should be added to blacklist
 */
function getIPsForBlacklist({ ruleFindingsList, isForSlackMessage = false } = {}) {
    console.log('[statisticsService] Determining a list of IPs for blacklist...');
    const ipsBlacklist = [];
    try {
        const uniqueRecordsPerIp = _.groupBy(ruleFindingsList, 'srcIpDetails.ip');
        let maliciousRequestsList, conditionForBlacklist;

        for (const ip of Object.keys(uniqueRecordsPerIp)) {
            maliciousRequestsList = _.groupBy(uniqueRecordsPerIp[ip], 'isRequestMalicious');
            console.debug('[statisticsService] Malicious requests list:', maliciousRequestsList);
            if (maliciousRequestsList['true']) {
                console.debug('[statisticsService] Min number of malicious request for blacklisting:',
                    constants.MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_HOUR);
                conditionForBlacklist = maliciousRequestsList['true'].length > constants.MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_HOUR;

                const reasonsForBlacklisting = _.uniq(_.concat([], ...maliciousRequestsList['true']
                    .map((item) => item.reasonsForBlacklisting)));
                const sampleIpRecord = maliciousRequestsList['true'].slice(0, 1)[0];

                if (isForSlackMessage && conditionForBlacklist) {
                    ipsBlacklist.push(`IP: ${sampleIpRecord.srcIpDetails.ip} `
                    + `:flag-${sampleIpRecord.srcIpDetails.country.toLowerCase()}:\n`
                    + `<${sampleIpRecord.srcIpDetails.abuseIpDBInfo}|AbuseIPDb> | `
                    + `<${sampleIpRecord.srcIpDetails.threatBookInfo}|Threat Book Info> | `
                    + `<${sampleIpRecord.srcIpDetails.virusTotalInfo}|VirusTotal>\n`
                    + `Reasons for blacklisting: ${reasonsForBlacklisting.join(', ')}`);
                } else if (conditionForBlacklist && !isForSlackMessage) {
                    ipsBlacklist.push({
                        ip: sampleIpRecord.srcIpDetails.ip,
                        reasonsForBlacklisting,
                        startDate: new Date(),
                        sampleIpRecord,
                    });
                }
            }
        }
    } catch (err) {
        console.log('[statisticsService] Error occured when defining IPs for blacklist:', err);
    }
    return ipsBlacklist;
}

/**
 * This function generates top urls list by sorting all captured by a rule urls using request length in
 * descending order and selecting top N (defined by _topItemsCount_ variable) items from the final list.
 * We decided to use this approach because usually longer request urls contains more interesting attack
 * payloads
 * @param {*} params - ruleFindingsList - findings for a selected rule, topItemsCount - number of items to return
 * from the final list, isForSlackMessage - return urls in format that is used for Slack messages. Otherwise, it will
 * return a list of top requested urls for a define rule. We later write them to a file and use for generating daily
 * analytics
 * @returns list of top urls per rules defined based on the aforementioned criteria
 */
function getTopUrlsListForRule({ ruleFindingsList, topItemsCount, isForSlackMessage = false } = {}) {
    console.log('[statisticsService] Determining a list of top request urls for a rule...');
    return _.reverse(
        _.sortBy(
            _.uniqBy(ruleFindingsList, 'fullRequestUrl'), [function(el) { return el.fullRequestUrl.length; }],
        ),
    ).slice(0, topItemsCount).map((el) => {
        if (isForSlackMessage)
            return utils.formatStringForSlackMessage({ tgtStr: el.fullRequestUrl, maxNumberOfElements: topItemsCount })
                + ` [ip: ${el.srcIpDetails.ip}]`;
        else
            return el;
    });
}

/**
 * This function generates top payloads list by sorting all captured by a rule payloads using payload length in
 * descending order and selecting top N (defined by _topItemsCount_ variable) items from the final list.
 * We decided to use this approach because usually longer detected payloads are used for more tricky attacks
 * @param {*} params - ruleFindingsList - findings for a selected rule, topItemsCount - number of items to return
 * from the final list, isForSlackMessage - return payloads in format that is used for Slack messages. Otherwise, it will
 * return a list of top requested payloads for a define rule. We later write them to a file and use for generating daily
 * analytics
 * @returns list of top payloads per rules defined based on the aforementioned criteria
 */
function getTopPayloadsListForRule({ ruleFindingsList, topItemsCount, isForSlackMessage = false } = {}) {
    return _.reverse(
        _.sortBy(
            _.uniqBy(ruleFindingsList, 'matchDetails'), [function(el) { return el.matchDetails.length; }],
        ),
    ).slice(0, topItemsCount).map((el) => {
        if (isForSlackMessage && el.matchDetails.length > 1)
            return utils.formatStringForSlackMessage({ tgtStr: el.matchDetails, maxNumberOfElements: topItemsCount })
                + ` [ip: ${el.srcIpDetails.ip}]`;
        else if (isForSlackMessage)
            return el.matchDetails;
        else
            return el;
    });
}

/**
 * This function is used to create required statistics for the Slack message. Here are some
 * principles that are used during this process:
 * 1. Top detected IPs are sorted in descending order by taking into account number of their invocations.
 * It helps to detect the most active IPs.
 * 2. Top urls are sorted by length (from previously filtered unique findings) because usually we are
 * looking for longer URIs that may contain exploit payload.
 * 3. Top payloads are sorted by length (from previously filtered unique findings) because we are
 * looking for longer payload first (they often contain IPs of external C2 servers and more).
 * @param {*} ruleDetails - Object: {ruleFindingsList: list of findings for the specified rule,
 * ruleName: name of the selected rule}
 * @returns Empty string if there are no findings for the specific rule. If there are findings, function returns
 * the following details: top unique detected ips, top unique urls (by length), top unique matched payloads.
 */
function prepareStatisticsForRule({ ruleFindingsList, ruleName, isForSlackMessage = false }) {
    console.log(`[statisticsService] Preparing statistics for ${ruleName} rule...`);
    console.debug('[statisticsService] Rule findings:', ruleFindingsList);
    if (ruleFindingsList.length === 0) {
        console.log(`[statisticsService] No findings detected for ${ruleName} rule.`);
        return isForSlackMessage ? '' : {};
    } else {
        const [topIpsList, topUrlsList, topPayloadsList] = [
            getTopIPsListForRule({ ruleFindingsList, topItemsCount: constants.TOP_ITEMS_COUNT, isForSlackMessage }),
            getTopUrlsListForRule({ ruleFindingsList, topItemsCount: constants.TOP_ITEMS_COUNT, isForSlackMessage }),
            getTopPayloadsListForRule({ ruleFindingsList, topItemsCount: constants.TOP_ITEMS_COUNT, isForSlackMessage }),
        ];

        /**
         * Below you can find a list of rules for which we do not need to determine IPs for blacklisting because
         * these IPs are already blocked by WAF based on blacklists. Up to date names of rules can be taken from
         * the worker-pool.js file
         */
        const rulesWithoutIPBlacklisting = [
            'AWSWAFSecurityAutomationsBlacklistRule',
            'AWSWAFSecurityAutomationsIPReputationListsRule',
        ];
        const ipsForBlacklist = rulesWithoutIPBlacklisting.includes(ruleName) ? []
            : getIPsForBlacklist({ ruleFindingsList, isForSlackMessage });

        console.debug('[statisticsService] Statistics:', topIpsList, topUrlsList, topPayloadsList);
        return {
            topIpsList, topUrlsList, topPayloadsList, ipsForBlacklist,
        };
    }
}

/**
 * Write obtained statistics to a JSON file. Information from this file is later
 * used for the daily analytics and in the notificationService.js, s3Service.js
 */
function saveCapturedRequestsStatisticsToFile() {
    console.log('[statisticsService] Preparing statistics for saving to a file...');
    const processedRecords = require(path.resolve(__dirname,
        `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`));
    const statisticsData = utils.generateGroupsForStatistics();
    let ruleStatistics;

    console.debug('[statisticsService] Generated groups for statistics:', statisticsData);
    for (const ruleName of Object.keys(processedRecords)) {
        ruleStatistics = prepareStatisticsForRule({
            ruleFindingsList: processedRecords[ruleName],
            ruleName: ruleName.split('Findings')[0],
        });
        statisticsData[ruleName.replace('Findings', 'Statistics')] = ruleStatistics;
    }
    console.log('[statisticsService] Saving processed AWS WAF records statistics to a file...');
    fs.writeFileSync(path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_STATISTICS_FILE_NAME}`),
        JSON.stringify(statisticsData));
}

/**
 * This function retrieves a list of IP addresses that should be blacklisted from the
 * statistics report generated by lambda
 * @returns list of IP addresses that should be blacklisted in format {
 *  ip: '<IP>',
 *  reasonsForBlacklisting: ['<REASON>', ...],
 *  startDate: '<DATE>',
 *  ipDetails: {
 *     country: '...',
 *     abuseIpDBInfo: '...',
 *     threatBookInfo: '...',
 *     virusTotalInfo: '...'
 *  }
 * }
 */
function getIpsForBlacklistingFromFile() {
    console.log('[statisticsService] Retrieving IPs that should be blacklisted from a file...');
    const statisticsReport = require(path.resolve(__dirname,
        `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_STATISTICS_FILE_NAME}`));
    const ipsList = [];

    for (const statisticsGroupName of Object.keys(statisticsReport)) {
        if (!_.isEmpty(statisticsReport[statisticsGroupName].ipsForBlacklist)) {
            statisticsReport[statisticsGroupName].ipsForBlacklist.map((ipRecord) => ipsList.push({
                ip: ipRecord.ip,
                reasonsForBlacklisting: ipRecord.reasonsForBlacklisting,
                startDate: ipRecord.startDate,
                ipDetails: {
                    country: ipRecord.sampleIpRecord.srcIpDetails.country.toLowerCase(),
                    abuseIpDBInfo: ipRecord.sampleIpRecord.srcIpDetails.abuseIpDBInfo,
                    threatBookInfo: ipRecord.sampleIpRecord.srcIpDetails.threatBookInfo,
                    virusTotalInfo: ipRecord.sampleIpRecord.srcIpDetails.virusTotalInfo,
                },
            }));
        }
    }

    return ipsList;
}

/**
 * This function updates a list of blacklisted IP addresses with new entries and
 * saves the final result to a file that is later uploaded to S3. IP addresses entries format:
 * {
 *  ip: '<IP>',
 *  reasonsForBlacklisting: ['<REASON>', ...],
 *  startDate: '<DATE>',
 *  ipDetails: {
 *      'country': '<COUNTRY>',
 *      'abuseIpDBInfo': '<LINK>',
 *      'threatBookInfo': '<LINK>',
 *      'virusTotalInfo': '<LINK>'
 *  }
 * }
 * @param {*} newlyBlacklistedIpsList - list of newly blacklisted IP addresses
 */
function updateBlacklistedIPsFileWithNewEntries(newlyBlacklistedIpsList) {
    if (_.isEmpty(newlyBlacklistedIpsList)) {
        console.log('[statisticsService] newlyBlacklistedIpsList is empty. Skipping update of file with blacklisted IPs...');
        return;
    }
    console.log('[statisticsService] Saving blacklisted IPs to a file...');
    const existingBlacklistedIPs = require(path.resolve(__dirname,
        `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`));
    for (const ipRecord of newlyBlacklistedIpsList) {
        if (_.findIndex(existingBlacklistedIPs, (record) => record.ip === ipRecord.ip) >= 0)
            console.log(`[statisticsService] IP ${ipRecord.ip} already exists in our blacklist. Skipping...`);
        else
            existingBlacklistedIPs.push(ipRecord);
    }
    fs.writeFileSync(
        path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`),
        JSON.stringify(existingBlacklistedIPs),
    );
}

/**
 * This function rewrites a list of blacklisted IP addresses with updated entries (after sync with AWS WAF IPSet) and
 * saves the final result to a file that is later uploaded to S3. IP addresses entries format:
 * {
 *  ip: '<IP>',
 *  reasonsForBlacklisting: ['<REASON>', ...],
 *  startDate: '<DATE>',
 *  ipDetails: {
 *      'country': '<COUNTRY>',
 *      'abuseIpDBInfo': '<LINK>',
 *      'threatBookInfo': '<LINK>',
 *      'virusTotalInfo': '<LINK>'
 *  }
 * }
 * @param {*} blacklistedIPsList - updated list of blacklisted IP addresses
 */
function rewriteBlacklistedIPsFileAfterSync(blacklistedIPsList) {
    if (_.isEmpty(blacklistedIPsList)) {
        console.log('[statisticsService] blacklistedIPsList is empty. Skipping rewrite of file with blacklisted IPs...');
        return;
    }
    console.log('[statisticsService] Rewriting file with blacklisted IPs after sync with AWS WAF IPSet...');
    fs.writeFileSync(
        path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`),
        JSON.stringify(blacklistedIPsList),
    );
}

/**
 * TODO: add unit tests for the statistics service
 */
module.exports = {
    getIPsForBlacklist,
    getTopIPsListForRule,
    getTopPayloadsListForRule,
    getTopUrlsListForRule,
    prepareStatisticsForRule,
    saveCapturedRequestsStatisticsToFile,
    getIpsForBlacklistingFromFile,
    updateBlacklistedIPsFileWithNewEntries,
    rewriteBlacklistedIPsFileAfterSync,
};
