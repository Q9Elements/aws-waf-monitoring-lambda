const fs = require('fs');
const path = require('path');
const _ = require('lodash');
const Piscina = require('piscina');
const constants = require('./constants');
const utils = require('./utils');

/**
 * Write the modified log records to a JSON file. Information from this file is later
 * used in notificationService.js and s3Service.js
 * @param {Object} findingsGroups - groups for findings, related to different AWS WAF rules
 */
function saveModifiedRecordsToFile(findingsGroups) {
    console.log('[logRecordsProcessor] Saving modified AWS WAF log records to a file...');
    fs.writeFileSync(path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`),
        JSON.stringify(findingsGroups));
}

/**
 * This function is used to process a list of logged by AWS WAF requests
 */
async function extractAndProcessWAFLogRecords() {
    const pool = new Piscina();
    const options = { filename: path.resolve(__dirname, './worker-pool.js') };
    let findingsGroups = utils.generateGroupsForDetectedIssues();

    try {
        console.log(`[logRecordsProcessor] Parsing AWS WAF logs from ${constants.TEMP_DIR_NAME}...`);
        const tempFilesDirName = path.resolve(__dirname, constants.TEMP_DIR_NAME);
        /**
         * Please note that numer of parallel threads and a number of findings in one chunk should be
         * selected based on the performance considerations. These are just sample settings.
         */
        const numberOfParallelThreads = 2;
        let fileContent, chunkedFindings, res;

        const filesList = fs.readdirSync(tempFilesDirName).filter((fileName) => fileName.endsWith('.log'));
        for (const fileName of filesList) {
            fileContent = fs.readFileSync(path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${fileName}`))
                .toString().split('\n').filter((el) => el !== '');
            console.debug('[logRecordsProcessor][fileContent]::', fileContent);
            chunkedFindings = _.chunk(fileContent, 500).map((groupEl) => pool.run(groupEl, options));
            for (let i = 0; i < chunkedFindings.length; i += numberOfParallelThreads) {
                res = await Promise.all(chunkedFindings.slice(i, i + numberOfParallelThreads));
                console.debug('[logRecordsProcessor][processedFindings]', res);
                findingsGroups = _.mergeWith(findingsGroups, ...res, (objValue, srcValue) => objValue.concat(srcValue));
            }
        }

        saveModifiedRecordsToFile(findingsGroups);
    } catch (err) {
        console.error('[logRecordsProcessor] Error occurred during parsing AWS WAF logs');
        console.error(err);
    }
}

module.exports = {
    extractAndProcessWAFLogRecords,
};
