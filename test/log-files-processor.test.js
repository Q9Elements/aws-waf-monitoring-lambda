const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const logFilesProcessor = require('../src/logFilesProcessor');
const logger = require('../src/logger');
const constants = require('../src/constants');

describe('Log files processor tests', () => {
    before(() => logger.setUpLogger());

    it('Should ensure that "removeTempFiles" function works correctly', () => {
        logFilesProcessor.removeTempLogFiles();
        expect(fs.existsSync(path.resolve(__dirname, constants.TEMP_DIR_NAME))).to.be.false;
    });

    it('Should ensure that "prepareTempDir" function works correctly', () => {
        logFilesProcessor.prepareTempDirForLogFiles();
        expect(fs.existsSync(path.resolve(__dirname, constants.TEMP_DIR_NAME))).to.be.true;
    });

    describe('Check "getAWSWAFLogsFromS3" functionality', () => {
        before(() => {
            logFilesProcessor.removeTempLogFiles();
            logFilesProcessor.prepareTempDirForLogFiles();
        });

        it('Should ensure that "getAWSWAFLogsFromS3" works as expected', async() => {
            await logFilesProcessor.getAWSWAFLogsFromS3();
            const tempFilesList = fs.readdirSync(path.resolve(__dirname, constants.TEMP_DIR_NAME));
            const sampleFilesList = fs.readdirSync(path.resolve(__dirname, './aws-waf-logs-samples/'));
            for (const file of sampleFilesList) {
                expect(tempFilesList).to.include(file);
                expect(tempFilesList).to.include(file.split('.gz')[0]);
            }
        });
    });

    after(() => {
        logFilesProcessor.removeTempLogFiles();
    });
});
