const path = require('path');
const constants = require('./constants');
const notificationService = require('./notificationService');
const analyticsService = require('./analyticsService');

/**
 * This function prepares Slack message template with analytics summary. Analytics summary details
 * are retrieved from the summary report file that is located at:
 * ${constants.ANALYTICS_REPORTS_DIR_NAME}/${constants.ANALYTICS_SUMMARY_REPORT_NAME}
 * @param {String} findingCategory - findings category (WAF rule)
 * @param {Object} additionalParams - includeHeader - add header section to message
 * @returns Slack message template
 */
function prepareAnalyticsReportTemplateForCategory(findingCategory, { includeHeader = false } = {}) {
    console.log('[templatesService] Creating analytics report template for Slack');
    console.debug(`[templatesService] Findings category: ${findingCategory}`);
    const [date, messageTemplate] = [new Date(), []];

    if (includeHeader)
        messageTemplate.push({
            type: 'header',
            text: {
                type: 'plain_text',
                text: `[${constants.ENV_NAME}] AWS WAF monitoring lambda analytics report ${date.toLocaleDateString()}`,
            },
        }, { type: 'divider' });

    const analyticsReport = require(path
        .resolve(__dirname, `${constants.ANALYTICS_REPORTS_DIR_NAME}/${constants.ANALYTICS_SUMMARY_REPORT_NAME}`));
    let record;

    if (analyticsReport[findingCategory][analyticsService.IP_STATS_PROPERTY_NAME].length > 0) {
        messageTemplate.push(...notificationService.generateMessageSectionTemplateSections({
            sectionNameTemplate: `*${analyticsReport[findingCategory].ruleId} rule summary* :bar_chart:`,
        }));
        for (let i = 0; i < constants.ANALYTICS_TOP_RECORDS_COUNT; i += 1) {
            if (i >= analyticsReport[findingCategory][analyticsService.IP_STATS_PROPERTY_NAME].length - 1)
                break;
            record = analyticsReport[findingCategory][analyticsService.IP_STATS_PROPERTY_NAME][i];
            console.debug('[templatesService] Record path: ', record);
            messageTemplate.push(...notificationService.generateMessageSectionTemplateSections({
                sectionNameTemplate: '',
                sectionContent: record[analyticsService.IP_THREAT_INTEL_PROPERTY_NAME].formattedMessage,
            }));
            messageTemplate.push(...notificationService.generateMessageSectionTemplateSections({
                sectionNameTemplate: `*Total count of requests: ${record.count}*`,
            }));
            messageTemplate.push(...notificationService.generateMessageSectionTemplateSections({
                sectionNameTemplate: '*Top requested URLs*\n',
                sectionContent: record[analyticsService.URL_STATS_PROPERTY_NAME].join('\n\n'),
                dispaySectionContentAsCodeBlock: true,
            }));
        }
    }

    return messageTemplate;
}

module.exports = {
    prepareAnalyticsReportTemplateForCategory,
};
