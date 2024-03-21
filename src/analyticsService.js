const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const constants = require('./constants');
const s3Service = require('./s3Service');
const utils = require('./utils');

/**
 * Local constants, used only for the analytics module
 */
const IP_STATS_PROPERTY_NAME = 'ipAnalyticsResults';
const URL_STATS_PROPERTY_NAME = 'urlsList';
const IP_THREAT_INTEL_PROPERTY_NAME = 'threatInfo';

/**
 * This function analyses findings from the processed reports per groups (rules) and creates a list
 * of IP addresses and their detection rates, sorted in descending order for further processing
 * @param {*} findingsGroups - collected findings from the downloaded reports
 * @param {*} analyticsGroups - analytics data
 * @returns analytics records with a list of IP addresses and their detection rates per group
 */
function calculateIpsPerGroup(findingsGroups, analyticsGroups) {
    console.log('[analyticsService] Determining detection rate of IPs per groups (rules)');
    Object.keys(findingsGroups).forEach((groupName) => {
        if (findingsGroups[groupName].length > 0)
            analyticsGroups[groupName].ruleId = findingsGroups[groupName][0].ruleId;
        analyticsGroups[groupName][IP_STATS_PROPERTY_NAME] = _.map(_.countBy(findingsGroups[groupName], 'srcIpDetails.ip'),
            function(value, key) { return { ip: key, count: value }; });
        analyticsGroups[groupName][IP_STATS_PROPERTY_NAME] = _.sortBy(analyticsGroups[groupName][IP_STATS_PROPERTY_NAME],
            [function(o) { return -o.count; }]);
    });
    return analyticsGroups;
}

/**
 * This function retrieves a list of top requested urls per IP (we use url length as selection criteria).
 * Number of findings is limited by the constants.ANALYTICS_TOP_RECORDS_COUNT variable
 * @param {*} findingsList - list of findings for the selected IP address
 * @returns list of top requested urls per IP address
 */
function getTopUrlsByIp(findingsList) {
    return _.reverse(
        _.sortBy(
            _.uniqBy(findingsList, 'fullRequestUrl'), [function(el) { return el.fullRequestUrl.length; }],
        ),
    ).slice(0, constants.ANALYTICS_TOP_RECORDS_COUNT).map((el) => {
        return utils.formatStringForSlackMessage({
            tgtStr: el.fullRequestUrl,
            maxNumberOfElements: constants.ANALYTICS_TOP_RECORDS_COUNT,
        }) + ` [ip: ${el.srcIpDetails.ip}]`;
    });
}

/**
 * This function analyses most interesting findings per group (rule) based on a list of IP addresses and their
 * detection rates. As a result, we will be able to use this information for blocking IP addresses that were
 * conducting vulnerability scans againt the infrastructure.
 * IMPORTANT NOTE: this function should be called only after the findings were processed by the calculateIpsPerGroup
 * function
 * @param {*} findingsGroups - collected findings from the downloaded reports
 * @param {*} analyticsGroups - analytics data
 * @returns analytics records with a list of typical urls per each IP address in the selected group (rule)
 */
function getTypicalUrlsListPerIps(findingsGroups, analyticsGroups) {
    console.log('[analyticsService] Determining typical requested urls per IP in every group');
    const isIpsDetailsPresent = Object.keys(analyticsGroups)
        .map((el) => _.has(analyticsGroups[el], IP_STATS_PROPERTY_NAME))
        .includes(true);
    if (isIpsDetailsPresent) {
        Object.keys(findingsGroups).forEach((groupName) => {
            analyticsGroups[groupName][IP_STATS_PROPERTY_NAME] = analyticsGroups[groupName][IP_STATS_PROPERTY_NAME]
                .map((ipRecord) => {
                    const ipDetections = findingsGroups[groupName].filter((el) => el.srcIpDetails.ip === ipRecord.ip);
                    return _.assignIn(ipRecord, { [URL_STATS_PROPERTY_NAME]: getTopUrlsByIp(ipDetections) });
                });
        });
    } else {
        console.log('[analyticsService] Error: cannot find IPs analytics inside the findingsGroups');
        Object.keys(findingsGroups).forEach((groupName) => {
            analyticsGroups[groupName][IP_STATS_PROPERTY_NAME] = analyticsGroups[groupName][IP_STATS_PROPERTY_NAME]
                .map((el) => _.assignIn(el, { [URL_STATS_PROPERTY_NAME]: [] }));
        });
    }
    return analyticsGroups;
}

/**
 * This function is used to add threat intelligence info for each IP address in the specified
 * group (rule)
 * @param {*} groupFindingsList - list of group (rule) findings
 * @param {*} analyticsGroupRecords - list of analysis records per group (rule)
 * @returns extracted threat intelligence information
 */
function addIpsThreatIntelInfo(groupFindingsList, analyticsGroupRecords) {
    let record;

    for (let i = 0; i < analyticsGroupRecords[IP_STATS_PROPERTY_NAME].length; i += 1) {
        record = _.find(groupFindingsList,
            ['srcIpDetails.ip', analyticsGroupRecords[IP_STATS_PROPERTY_NAME][i].ip]);
        analyticsGroupRecords[IP_STATS_PROPERTY_NAME][i][IP_THREAT_INTEL_PROPERTY_NAME] = {
            abuseIpDBInfo: record.srcIpDetails.abuseIpDBInfo,
            threatBookInfo: record.srcIpDetails.threatBookInfo,
            virusTotalInfo: record.srcIpDetails.virusTotalInfo,
            formattedMessage: `*IP*: ${record.srcIpDetails.ip} :flag-${record.srcIpDetails.country.toLowerCase()}:; `
            + `<${record.srcIpDetails.abuseIpDBInfo}|AbuseIPDb> | `
            + `<${record.srcIpDetails.threatBookInfo}|Threat Book Info> | `
            + `<${record.srcIpDetails.virusTotalInfo}|VirusTotal>\n`,
        };
    }

    return analyticsGroupRecords;
}

/**
 * This functions reads information from ${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}
 * file where we store blacklisted IPs (it is also uploaded to S3), filters retrieved information and
 * return a list of IPs that were blacklisted during the last 24 hours. This information is later sent
 * to Slack
 * @returns list of recently blacklisted IPs (during the last 24 hours)
 */
function getBlacklistedDuringPreviousDayIPs({
    blacklistFilePath = `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`,
} = {}) {
    console.log('[analyticsService] Getting a list of blacklisted during the last 24 hours IPs...');
    const existingBlacklistedIPs = require(blacklistFilePath);
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 1);
    return existingBlacklistedIPs.filter((ipRecord) => new Date(ipRecord.startDate) > startDate);
}

/**
 * This function saves analytics summary report to a file.
 * @param {*} analyticsGroups - analytics data
 */
function saveAnalyticsSummaryReport(analyticsGroups) {
    const summaryReportFilePath = path
        .resolve(__dirname, `${constants.ANALYTICS_REPORTS_DIR_NAME}/${constants.ANALYTICS_SUMMARY_REPORT_NAME}`);
    console.log(`[analyticsService] Saving analytics summary report to a file (${summaryReportFilePath})`);
    fs.writeFileSync(summaryReportFilePath, JSON.stringify(analyticsGroups));
}

/**
 * This function is used to process information from downloaded lambda reports and save results to a file.
 */
async function processLambdaReports() {
    console.log('[analyticsService] Processing lambda reports...');
    const reportsFilesList = fs.readdirSync(path.resolve(__dirname, constants.ANALYTICS_REPORTS_DIR_NAME));
    const findingsGroups = utils.generateGroupsForDetectedIssues();
    let analyticsGroups = utils.generateGroupsForAnalytics();
    let reportContent;

    for (const reportFileName of reportsFilesList) {
        console.debug(`[analyticsService] Processing ${reportFileName} report`);
        reportContent = require(path.resolve(__dirname, `${constants.ANALYTICS_REPORTS_DIR_NAME}/${reportFileName}`));
        Object.keys(reportContent).forEach((findinggroup) => {
            if (_.isArray(reportContent[findinggroup]) && reportContent[findinggroup].length > 0)
                findingsGroups[findinggroup].push(...reportContent[findinggroup]);
        });
    }

    analyticsGroups = calculateIpsPerGroup(findingsGroups, analyticsGroups);
    analyticsGroups = getTypicalUrlsListPerIps(findingsGroups, analyticsGroups);
    Object.keys(analyticsGroups).forEach((groupName) => {
        analyticsGroups[groupName] = addIpsThreatIntelInfo(findingsGroups[groupName], analyticsGroups[groupName]);
    });
    saveAnalyticsSummaryReport(analyticsGroups);
}

/**
 * This function retrieves AWS WAF monitoring lambda reports from S3 and saves them to a temp folder.
 * @param {*} params - numberOfReportsToAnalyze - by default, it analyze reports for last 12 hours
 */
async function getLambdaReportsFromS3({
    numberOfReportsToAnalyze = 12,
} = {}) {
    try {
        console.log('[analyticsService] Retrieving AWS WAF logs from S3');
        console.debug(`[analyticsService] Number of reports to analyze: ${numberOfReportsToAnalyze}`);
        let availableReportFiles, reportFileData;

        for (let i = 0; i < numberOfReportsToAnalyze; i += 1) {
            availableReportFiles = await s3Service.listS3BucketObjects({
                prefix: s3Service.getObjectPrefixForGetLambdaReportS3Query({ timeShiftHours: -i }),
            });
            console.log('[analyticsService] Retrieved report files:', availableReportFiles);
            for (const file of availableReportFiles.Contents) {
                if (file.Key.includes(constants.OUTPUT_LOG_RECORDS_FILE_NAME)) {
                    reportFileData = await s3Service.getObjectFromS3Bucket({
                        key: file.Key,
                        transformResponseBodyToString: true,
                    });
                    console.debug('[analyticsService] Data:', reportFileData);
                    console.debug('[analyticsService] Saving downloaded JSON report to '
                        + constants.ANALYTICS_REPORTS_DIR_NAME);
                    fs.writeFileSync(path.resolve(__dirname, `${constants.ANALYTICS_REPORTS_DIR_NAME}/`
                        + `${constants.ANALYTICS_REPORT_NAME_TEMPLATE}${i}.json`), reportFileData);
                    break;
                }
            }
        }
    } catch (err) {
        console.error('[analyticsService] Error occurred during retrieving lambda reports from S3');
        console.error(err);
    }
}

/**
 * This function prepares folder for temp files that are used for creating analytics
 */
function prepareTempDirForAnalytics() {
    console.log('[analyticsService] Creating dir for analytics temp files...');
    utils.prepareTempDir(constants.ANALYTICS_REPORTS_DIR_NAME);
}

/**
 * This function will remove analytics temp files. We need to remove temp files from /tmp lambda storage
 * manually because it is not an automated process.
 */
function removeAnalyticsTempFiles() {
    console.log('[analyticsService] Removing temp files...');
    utils.removeTempFiles(constants.ANALYTICS_REPORTS_DIR_NAME);
}

module.exports = {
    getLambdaReportsFromS3,
    prepareTempDirForAnalytics,
    removeAnalyticsTempFiles,
    processLambdaReports,
    saveAnalyticsSummaryReport,
    getBlacklistedDuringPreviousDayIPs,
    IP_STATS_PROPERTY_NAME,
    IP_THREAT_INTEL_PROPERTY_NAME,
    URL_STATS_PROPERTY_NAME,
};
