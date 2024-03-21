const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const logFilesProcessor = require('../src/logFilesProcessor');
const logsRecordsProcessor = require('../src/logRecordsProcessor');
const logger = require('../src/logger');
const constants = require('../src/constants');

/**
 * Up to date list of sections can be taken from aws-waf-monitoring-lambda/src/utils.js file
 */
const outputFileSections = [
    'scannersAndProbesFindings',
    'xssFindings',
    'sqlInjectionFindings',
    'ipReputationRuleFindings',
    'blackListRuleFindings',
];

describe('Log records processor tests', () => {
    before(async() => {
        logger.setUpLogger();
        logFilesProcessor.removeTempLogFiles();
        logFilesProcessor.prepareTempDirForLogFiles();
        await logFilesProcessor.getAWSWAFLogsFromS3();
    });

    it('Should ensure that "extractAndProcessWAFLogRecords" works as expected', async() => {
        await logsRecordsProcessor.extractAndProcessWAFLogRecords();
        const tempFilesList = fs.readdirSync(path.resolve(__dirname, constants.TEMP_DIR_NAME));
        expect(tempFilesList).to.include(constants.OUTPUT_LOG_RECORDS_FILE_NAME);
    });

    it(`Should ensure that "${constants.OUTPUT_LOG_RECORDS_FILE_NAME}" file contains correct sections`, () => {
        const outputReport = require(path.resolve(__dirname,
            `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`));
        expect(Object.keys(outputReport)).to.have.members(outputFileSections);
    });

    it('Should ensure that processed log records contains analysis results (isRequestMalicious)', () => {
        const outputReport = require(path.resolve(__dirname,
            `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`));
        for (const findingsGroupName of Object.keys(outputReport))
            if (outputReport[findingsGroupName].length > 0)
                outputReport[findingsGroupName].forEach((logRecord) => {
                    expect(logRecord).to.have.property('isRequestMalicious');
                    expect(typeof logRecord.isRequestMalicious).to.equal('boolean');
                });
    });

    it('Should ensure that processed log records contains analysis results (reasonsForBlacklisting)', () => {
        const outputReport = require(path.resolve(__dirname,
            `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_LOG_RECORDS_FILE_NAME}`));
        for (const findingsGroupName of Object.keys(outputReport))
            if (outputReport[findingsGroupName].length > 0)
                outputReport[findingsGroupName].forEach((logRecord) => {
                    expect(logRecord).to.have.property('isRequestMalicious');
                    if (logRecord.isRequestMalicious) {
                        expect(logRecord).to.have.property('reasonsForBlacklisting');
                        expect(logRecord.reasonsForBlacklisting.length).to.be.greaterThan(0);
                    }
                });
    });

    after(() => {
        logFilesProcessor.removeTempLogFiles();
    });
});
