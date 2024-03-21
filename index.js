const _ = require('lodash');
const logFilesProcessor = require('./src/logFilesProcessor');
const logsRecordsProcessor = require('./src/logRecordsProcessor');
const notificationService = require('./src/notificationService');
const analyticsService = require('./src/analyticsService');
const templatesService = require('./src/templatesService');
const statisticsService = require('./src/statisticsService');
const s3Service = require('./src/s3Service');
const wafService = require('./src/wafService');
const constants = require('./src/constants');
const utils = require('./src/utils');
const logger = require('./src/logger');

// eslint-disable-next-line no-unused-vars
module.exports.handler = async function (event, context) {
    logger.setUpLogger();
    logFilesProcessor.removeTempLogFiles();
    logFilesProcessor.prepareTempDirForLogFiles();

    console.log('[index.js] Started AWS WAF monitoring lambda');

    const dateRecords = (new Date()).toLocaleString('en-US', { timeZone: 'Europe/London' }).split(' ');

    if (dateRecords[2] === 'AM' && dateRecords[1].split(':')[0] === '09' && dateRecords[1].split(':')[1] === '30') {
        /**
         * Prepare and send daily analytics every day at 09:30 Europe/London time
         */
        analyticsService.removeAnalyticsTempFiles();
        analyticsService.prepareTempDirForAnalytics();
        await analyticsService.getLambdaReportsFromS3();
        await analyticsService.processLambdaReports();

        const findingsGroups = utils.generateGroupsForAnalytics();
        let template;

        for (const groupName of Object.keys(findingsGroups)) {
            template = templatesService.prepareAnalyticsReportTemplateForCategory(
                groupName,
                { includeHeader: Object.keys(findingsGroups).indexOf(groupName) === 0 },
            );
            if (template.length >= 2)
                await notificationService.sendSlackMessage(template);
        }

        /**
         * Define IPs that were blacklisted during the last 24 hours and send them to Slack
         */
        await s3Service.retrieveFileWithBlacklistedIPsFromS3();
        const recentlyBlacklistedIPs = analyticsService.getBlacklistedDuringPreviousDayIPs();

        if (!_.isEmpty(recentlyBlacklistedIPs)) {
            let finalSlackMessageText = '',
                country;

            for (const ipRecord of recentlyBlacklistedIPs) {
                country = ipRecord.ipDetails.country === constants.NEUTRAL_FLAG_FOR_SLACK_MESSAGE
                    ? `${ipRecord.ipDetails.country}\n` : `:flag-${ipRecord.ipDetails.country}:\n`;
                finalSlackMessageText += `IP: ${ipRecord.ip} `
                    + country
                    + `<${ipRecord.ipDetails.abuseIpDBInfo}|AbuseIPDb> | `
                    + `<${ipRecord.ipDetails.threatBookInfo}|Threat Book Info> | `
                    + `<${ipRecord.ipDetails.virusTotalInfo}|VirusTotal>\n`
                    + `Reasons for blacklisting: ${ipRecord.reasonsForBlacklisting.join(', ')}\n\n`;
            }

            const slackMessageBlocks = notificationService.generateMessageSectionTemplateSections({
                sectionNameTemplate: '*Blacklisted IP addresses (last 24 hours)*\n',
                sectionContent: finalSlackMessageText,
            });
            await notificationService.sendSlackMessage(slackMessageBlocks);
        }

        /**
         * Cleanup temporary files
         */
        logFilesProcessor.removeTempLogFiles();
        analyticsService.removeAnalyticsTempFiles();
    } else {
        /**
         * Prepare and send hourly analytics
         */
        await logFilesProcessor.getAWSWAFLogsFromS3();
        await logsRecordsProcessor.extractAndProcessWAFLogRecords();
        await s3Service.sendProcessedDataToS3();
        await notificationService.formStatisticsAndSendItToTeam();
        await statisticsService.saveCapturedRequestsStatisticsToFile();
        await s3Service.sendProcessedDataToS3({ fileName: constants.OUTPUT_STATISTICS_FILE_NAME });
        /**
         * Add detected malicious IP addresses to blacklist
         */
        await s3Service.retrieveFileWithBlacklistedIPsFromS3();
        const ipsForBlacklist = statisticsService.getIpsForBlacklistingFromFile();
        const newlyBlacklistedIpsList = [];
        let blacklistUpdateResult;

        await wafService.makeBlacklistsUpToDate();

        for (const ipRecord of ipsForBlacklist) {
            console.log(`[index.js] Adding ${ipRecord.ip} to blacklist...`);
            blacklistUpdateResult = await wafService.addNewIPAddressToBlacklist(ipRecord.ip);
            if (blacklistUpdateResult)
                newlyBlacklistedIpsList.push(ipRecord);
        }
        statisticsService.updateBlacklistedIPsFileWithNewEntries(newlyBlacklistedIpsList);
        await s3Service.sendIPsBlacklistToS3();
        /**
         * Cleanup temporary files
         */
        logFilesProcessor.removeTempLogFiles();
    }
};
