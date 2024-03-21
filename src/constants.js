/* eslint-disable no-useless-escape */
require('dotenv').config();

/**
 * Constants
 */
const TEMP_DIR_NAME = process.env.TEMP_DIR_NAME || '../temp_files';
const OUTPUT_LOG_RECORDS_FILE_NAME = process.env.OUTPUT_LOG_RECORDS_FILE_NAME || 'processedAWSWAFLogRecords.json';
const OUTPUT_STATISTICS_FILE_NAME = process.env.OUTPUT_STATISTICS_FILE_NAME || 'processedRecordsStatistics.json';
const OUTPUT_BLACKLISTED_IPS_FILE_NAME = process.env.OUTPUT_BLACKLISTED_IPS_FILE_NAME || 'blacklistedIPs.json';
const AWS_WAF_RULES_LIST = [
    'AWSWAFSecurityAutomationsIPReputationListsRule', 'AWSWAFSecurityAutomationsSqlInjectionRule',
    'AWSWAFSecurityAutomationsXSSRule', 'AWSWAFSecurityAutomationsScannersAndProbesRule',
    'AWSWAFSecurityAutomationsBlacklistRule',
];
const AWS_ACCOUNT_ID = process.env.AWS_ACCOUNT_ID || '';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_AWS_WAF_LOGS_BUCKET_NAME = process.env.S3_AWS_WAF_LOGS_BUCKET_NAME || '';
const S3_AWS_WAF_LOGS_BUCKET_FOLDER_PREFIX = process.env.S3_AWS_WAF_LOGS_BUCKET_FOLDER_PREFIX
    || 'WAFLogs/us-east-1/AWSWAFSecurityAutomations/';
const S3_UPLOAD_FOLDER_NAME = process.env.S3_UPLOAD_FOLDER_NAME || '';
const SEND_PROCESSED_DATA_TO_S3 = process.env.SEND_PROCESSED_DATA_TO_S3 || 'true';
const LOG_LEVEL = process.env.LOG_LEVEL || 'debug';
const ENV_NAME = process.env.ENV_NAME || 'Production';
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || 'http://127.0.0.1:5000/';
const NO_DETECTIONS_SLACK_MESSAGE_TEMPLATE = [{
    type: 'section',
    text: {
        type: 'plain_text',
        text: 'Not detected any malicious traffic during the last hour',
    },
}];

/**
 * AWS WAF IPSets details
 */
const AWS_WAF_IPV4_BLACKLIST_NAME = process.env.AWS_WAF_IPV4_BLACKLIST_NAME || 'AWSWAFBlacklistSetIPV4';

/**
 * Blacklisting functions settings
 */
const MAX_TIME_FOR_BLACKLISTING_HOURS = process.env.MAX_TIME_FOR_BLACKLISTING_HOURS || 24;
const NEUTRAL_FLAG_FOR_SLACK_MESSAGE = process.env.NEUTRAL_FLAG_FOR_SLACK_MESSAGE || ':white_small_square:';

/**
 * AWS WAF monitoring lambda statistics service settings
 */
const TOP_ITEMS_COUNT = process.env.TOP_ITEMS_COUNT || 5;

/**
 * AWS WAF reports analytics settings
 */
const ANALYTICS_REPORTS_DIR_NAME = process.env.ANALYTICS_REPORTS_DIR_NAME || '/tmp/analytics';
const ANALYTICS_REPORT_NAME_TEMPLATE = process.env.ANALYTICS_REPORT_NAME_TEMPLATE || 'lambdaReport-';
const ANALYTICS_TOP_RECORDS_COUNT = Number(process.env.ANALYTICS_TOP_RECORDS_COUNT) || 5;
const ANALYTICS_SUMMARY_REPORT_NAME = process.env.ANALYTICS_SUMMARY_REPORT_NAME || 'analyticsSummaryReport.json';

/**
 * AWS WAF monitoring lambda analytics settings
 */
const MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_HOUR = process.env.MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_HOUR || 1;
const MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_DAY = process.env.MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_DAY || 1;
const REASONS_FOR_BLACKLISTING_IP = {
    XSS: 'XSS attack attempts',
    SQLI: 'SQL injection attack attemps',
};

/**
 * Notification service settings
 */
const MAX_SLACK_MESSAGE_LENGTH = process.env.MAX_SLACK_MESSAGE_LENGTH || 3000;

module.exports = {
    /**
     * General settings
     */
    TEMP_DIR_NAME,
    OUTPUT_LOG_RECORDS_FILE_NAME,
    OUTPUT_STATISTICS_FILE_NAME,
    OUTPUT_BLACKLISTED_IPS_FILE_NAME,
    AWS_WAF_RULES_LIST,
    AWS_ACCOUNT_ID,
    AWS_REGION,
    S3_AWS_WAF_LOGS_BUCKET_NAME,
    S3_AWS_WAF_LOGS_BUCKET_FOLDER_PREFIX,
    S3_UPLOAD_FOLDER_NAME,
    SEND_PROCESSED_DATA_TO_S3,
    LOG_LEVEL,
    ENV_NAME,
    SLACK_WEBHOOK_URL,
    NO_DETECTIONS_SLACK_MESSAGE_TEMPLATE,
    /**
     * AWS WAF monitoring lambda statistics service settings
     */
    TOP_ITEMS_COUNT,
    /**
     * Blacklisting functions settings
     */
    MAX_TIME_FOR_BLACKLISTING_HOURS,
    NEUTRAL_FLAG_FOR_SLACK_MESSAGE,
    /**
     * AWS WAF IPSets details
     */
    AWS_WAF_IPV4_BLACKLIST_NAME,
    /**
     * AWS WAF reports analytics settings
     */
    ANALYTICS_REPORTS_DIR_NAME,
    ANALYTICS_REPORT_NAME_TEMPLATE,
    ANALYTICS_TOP_RECORDS_COUNT,
    ANALYTICS_SUMMARY_REPORT_NAME,
    /**
     * AWS WAF monitoring lambda analytics settings
     */
    MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_HOUR,
    MIN_NUMBER_OF_REQUESTS_FOR_BLOCK_DAY,
    REASONS_FOR_BLACKLISTING_IP,
    /**
     * Notification service settings
     */
    MAX_SLACK_MESSAGE_LENGTH,
};
