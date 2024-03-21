const axios = require('axios');
const _ = require('lodash');
const path = require('path');
const constants = require('./constants');
const statisticsService = require('./statisticsService');

/**
 * Send message with results of log processing to the team
 * @param {*} messageBlocks - message body. Sample structure:
 * [
 *  {
 *      type: 'section',
 *      text: {
 *          type: 'mrkdwn',
 *          text: ':warning: *AWS WAF XSS rule results*'
 *      },
 *      fields: [
 *      {
 *          type: 'mrkdwn',
 *          text: `Top IPs: ${topIpsList}`
 *      },
 *      {
 *          type: 'mrkdwn',
 *          text: `Sample payloads: ${payloadsList}`
 *      }]
 *  }
 * ]
 * @param {*} webHookUrl - Slack webhook url
 */
async function sendSlackMessage(messageBlocks, webHookUrl = constants.SLACK_WEBHOOK_URL) {
    console.log('[notificationService] Sending results to Slack...');
    const preparedMessage = {
        blocks: messageBlocks,
    };
    try {
        console.debug('[notificationService] Final slack message:', JSON.stringify(preparedMessage));
        await axios.post(webHookUrl, preparedMessage);
    } catch (error) {
        console.log('[notificationService] Error occured during sending results to Slack:');
        console.log(error);
    }
}

/**
 * This function is used to divide Slack message content to smaller chunks because of the limitations.
 * Slack limits size of a single section to constants.MAX_SLACK_MESSAGE_LENGTH characters
 * @param {*} originalMessage - original Slack message content
 * @returns chunked Slack message content that does not exceed the max allowed message length
 */
function divideSlackMessageToSmallerChunks(originalMessage) {
    const messageChunks = [];

    if (originalMessage.length > 0 && originalMessage.length > constants.MAX_SLACK_MESSAGE_LENGTH) {
        const chunkSize = constants.MAX_SLACK_MESSAGE_LENGTH - 500;
        let searchStartIndex, currChunkEndIndex, sliceStartIndex;

        /**
         * We use chunks that have approximately (constants.MAX_SLACK_MESSAGE_LENGTH - 500) symbols in order to be sure that
         * all works as expected. Larger chunks (constants.MAX_SLACK_MESSAGE_LENGTH - 100) can sometimes be very tricky and
         * some strings can be broken
         */
        for (let i = 0; i < Math.floor(originalMessage.length / chunkSize) + 1; i += 1) {
            searchStartIndex = (i + 1) * chunkSize;
            currChunkEndIndex = originalMessage.indexOf('\n\n', searchStartIndex);
            messageChunks.push(originalMessage.slice(sliceStartIndex || 0, currChunkEndIndex));
            sliceStartIndex = currChunkEndIndex;
        }
    } else if (originalMessage.length > 0) {
        messageChunks.push(originalMessage);
    }

    return messageChunks;
}

/**
 * This function generates a new message section based on predefined template
 * @param {*} params - sectionNameTemplate - title of the section,
 * sectionContent - text that you would like to add to the section
 * @returns generated message section
 */
function generateMessageSectionTemplateSections({
    sectionNameTemplate,
    sectionContent,
    dispaySectionContentAsCodeBlock = false,
} = {}) {
    const finalTemplate = [];

    if (!sectionContent || _.isEmpty(sectionContent))
        finalTemplate.push({
            type: 'section',
            text: { type: 'mrkdwn', text: sectionNameTemplate },
        });
    else {
        const chunkedSections = divideSlackMessageToSmallerChunks(sectionContent);
        for (const section of chunkedSections)
            if (dispaySectionContentAsCodeBlock)
                finalTemplate.push({
                    type: 'section',
                    text: { type: 'mrkdwn', text: sectionNameTemplate + '```' + section + '```' },
                });
            else
                finalTemplate.push({
                    type: 'section',
                    text: { type: 'mrkdwn', text: `${sectionNameTemplate}${section}` },
                });
    }
    return finalTemplate;
}

/**
 * This function generates a new block that contains details about rule's action
 * for final Slack message
 * @param {*} ruleDetails - Object: {ruleFindingsList: list of findings for the specified rule,
 * ruleName: name of the selected rule}
 * @returns generated message block.
 */
function generateRuleActionSection({ ruleFindingsList, ruleName }) {
    console.log(`[notificationService] Generation rule action section for ${ruleName} rule...`);
    console.debug('[notificationService] Rule action:', ruleFindingsList);
    if (ruleFindingsList.length === 0) {
        console.log(`[notificationService] No findings detected for ${ruleName} rule.`);
        return '';
    } else {
        return generateMessageSectionTemplateSections({
            sectionNameTemplate: '*Rule action*\n',
            sectionContent: `${ruleFindingsList[0].action}`,
        })[0];
    }
}

/**
 * This functions extracts processed AWS WAF log records, divided by categories (rule names),
 * forms statistics and sends results to Slack.
 */
async function formStatisticsAndSendItToTeam() {
    const processedRecords = require(path.resolve(__dirname,
        `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`));
    let ruleStatistics, slackMessage;

    const detectionsCount = _.sum(Object.keys(processedRecords)
        .map((ruleName) => processedRecords[ruleName.toString()].length));

    if (detectionsCount === 0)
        await sendSlackMessage(constants.NO_DETECTIONS_SLACK_MESSAGE_TEMPLATE);
    else {
        for (const ruleName of Object.keys(processedRecords)) {
            ruleStatistics = statisticsService.prepareStatisticsForRule({
                ruleFindingsList: processedRecords[ruleName.toString()],
                ruleName: ruleName.split('Findings')[0],
                isForSlackMessage: true,
            });
            if (ruleStatistics !== '') {
                slackMessage = [{
                    type: 'header',
                    text: {
                        type: 'plain_text',
                        text: `[${constants.ENV_NAME}] ${processedRecords[ruleName.toString()][0].ruleId} rule results`,
                    },
                }];
                slackMessage.push(generateRuleActionSection({
                    ruleFindingsList: processedRecords[ruleName.toString()],
                    ruleName: ruleName.split('Findings')[0],
                }));
                slackMessage.push(...generateMessageSectionTemplateSections({
                    sectionNameTemplate: '*Top IPs list*\n',
                    sectionContent: ruleStatistics.topIpsList.join('\n\n'),
                }));
                slackMessage.push(...generateMessageSectionTemplateSections({
                    sectionNameTemplate: '*Top requested URLs*\n',
                    sectionContent: ruleStatistics.topUrlsList.join('\n\n'),
                    dispaySectionContentAsCodeBlock: true,
                }));
                slackMessage.push(...generateMessageSectionTemplateSections({
                    sectionNameTemplate: '*Top payloads*\n',
                    sectionContent: (ruleStatistics.topPayloadsList.join('\n\n') || 'no payloads detected'),
                    dispaySectionContentAsCodeBlock: true,
                }));
                if (ruleStatistics.ipsForBlacklist.length > 0)
                    slackMessage.push(...generateMessageSectionTemplateSections({
                        sectionNameTemplate: '*Blacklisted IP addresses*\n',
                        sectionContent: ruleStatistics.ipsForBlacklist.join('\n\n'),
                    }));
                await sendSlackMessage(slackMessage);
            }
        }
    }
}

module.exports = {
    formStatisticsAndSendItToTeam,
    generateMessageSectionTemplateSections,
    sendSlackMessage,
};
