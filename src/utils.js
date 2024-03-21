const _ = require('lodash');
const fs = require('fs');
const path = require('path');

/**
 * Used to sanitize included in payload links from being queried by Slack
 * @param {*} item - text to sanitize
 * @returns sanitized item
 */
function sanitizeLinks(item) {
    return item.replace('://', '[:]//');
}

/**
 * Modifies date parameters to construct correct queries to S3 bucket
 * Example: 3 -> 03, 9 -> 09
 * @param {*} dateParam - date, month
 * @param {*} addDelimiter - used to follow structure of the S3 bucket that
 * contains AWS WAF logs
 * @returns modified date value for queriyng S3
 */
function prepareDateParameterForQuery(dateParam, addDelimiter = true) {
    const updatedParam = dateParam < 10 ? `0${dateParam}` : dateParam.toString();
    return addDelimiter ? `${updatedParam}/` : updatedParam;
}

/**
 * This functions generates a list of variables that have Array type and will
 * be later used to store processed AWS WAF detections
 * @returns list of initialized groups for detected issues
 */
function generateGroupsForDetectedIssues() {
    return {
        scannersAndProbesFindings: [],
        xssFindings: [],
        sqlInjectionFindings: [],
        blackListRuleFindings: [],
        ipReputationRuleFindings: [],
    };
}

/**
 * This functions generates a list of variables that have Object type and will
 * be later used to store processed analytics results
 * @returns list of initialized groups for analytics results
 */
function generateGroupsForAnalytics() {
    const groupsList = generateGroupsForDetectedIssues();
    _.forEach(groupsList, function(value, key) {
        groupsList[key] = {};
    });
    return groupsList;
}

/**
 * This functions generates a list of variables that have Object type and will
 * be later used to store statistics data
 * @returns list of initialized groups for calculated statistics
 */
function generateGroupsForStatistics() {
    const groupsFindingsList = generateGroupsForDetectedIssues();
    const groupsStatistics = {};
    _.forEach(groupsFindingsList, function(value, key) {
        groupsStatistics[key.replace('Findings', 'Statistics')] = {};
    });
    return groupsStatistics;
}

/**
 * This function helps to modify received string, so it won't exceed Slack limitations
 * when added to a section element (3000 symbols)
 * @param {Object} params - tgtStr: string that should be modified,
 * maxNumberOfElements - max number of elements in the top list
 * @returns modified string if it exceeds allowed length or a string itself if all is ok
 */
function formatStringForSlackMessage({ tgtStr, maxNumberOfElements }) {
    /**
     * Additional 40 symbols are reserved for the final string with IP address from which
     * the requests were sent and appropriate message that informs a message reviewer about
     * limitations (for example, [...rest of string] [ip: 192.168.0.1])
     */
    const maxLengthForItem = Math.floor(3000 / maxNumberOfElements) - 40;
    if (tgtStr.length > maxLengthForItem)
        return `${tgtStr.substr(0, maxLengthForItem)}[...rest of string]`;
    else
        return tgtStr;
}

/**
 * This function prepares folder for temp files that are created during logs processing
 * @param {String} tgtDirPath - path to the target directory
 */
function prepareTempDir(tgtDirPath) {
    console.log('[utils] Creating dir for temp files...');
    const dirPath = path.resolve(__dirname, tgtDirPath);
    if (fs.existsSync(dirPath))
        console.log(`[utils] Dir for temp files (${dirPath}) already exists. Skipped this step`);
    else {
        fs.mkdirSync(path.resolve(__dirname, tgtDirPath));
        console.log(`[utils] Successfully created directory to store temp files (${dirPath})!`);
    }
}

/**
 * This function will remove temp files from the specified directory
 * @param {String} tgtDirPath - path to the target directory
 */
function removeTempFiles(tgtDirPath) {
    console.log(`[utils] Removing temp files from ${tgtDirPath}...`);
    const dirPath = path.resolve(__dirname, tgtDirPath);
    if (!fs.existsSync(dirPath))
        console.log(`[utils] Dir for temp files (${tgtDirPath}) is already deleted. Skipped this step`);
    else {
        const tmpFilesList = fs.readdirSync(dirPath);
        for (const tmpFile of tmpFilesList) {
            fs.rmSync(`${dirPath}/${tmpFile}`);
            console.log(`[utils] Removed ${tmpFile}`);
        }
        fs.rmdirSync(dirPath);
        console.log('[utils] Cleanup finished successfully!');
    }
}

module.exports = {
    prepareDateParameterForQuery,
    generateGroupsForDetectedIssues,
    generateGroupsForAnalytics,
    generateGroupsForStatistics,
    sanitizeLinks,
    formatStringForSlackMessage,
    prepareTempDir,
    removeTempFiles,
};
