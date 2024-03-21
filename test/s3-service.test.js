const fs = require('node:fs');
const path = require('node:path');
const { expect } = require('chai');
const logFilesProcessor = require('../src/logFilesProcessor');
const logsRecordsProcessor = require('../src/logRecordsProcessor');
const logger = require('../src/logger');
const s3Service = require('../src/s3Service');
const constants = require('../src/constants');
const ipsBlacklistFileName = path.resolve(__dirname,
    `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`);

/**
 * Up to date format of IP blacklist records can be reviewed in the
 * aws-waf-monitoring-lambda/src/statisticsService.js file
 */
const sampleIPBlacklistRecord = {
    ip: '192.168.0.1',
    reasonsForBlacklisting: ['XSS attack attempt'],
    startDate: new Date(),
};

describe('S3 service tests', () => {
    before(async() => {
        logger.setUpLogger();
        logFilesProcessor.removeTempLogFiles();
        logFilesProcessor.prepareTempDirForLogFiles();
        await logFilesProcessor.getAWSWAFLogsFromS3();
        await logsRecordsProcessor.extractAndProcessWAFLogRecords();
    });

    describe('Check that S3 upload function ("sendProcessedDataToS3") works correctly', () => {
        it('Should ensure that "sendProcessedDataToS3" works as expected', async() => {
            const res = await s3Service.sendProcessedDataToS3();
            expect(res).to.be.true;
        });
    });

    describe('Check that S3 upload functions works correctly', () => {
        before(() => {
            if (!fs.existsSync(ipsBlacklistFileName))
                fs.writeFileSync(ipsBlacklistFileName, JSON.stringify([sampleIPBlacklistRecord]));
        });

        it('Should ensure that "sendIPsBlacklistToS3" works as expected', async() => {
            const res = await s3Service.sendIPsBlacklistToS3();
            expect(res).to.be.true;
        });
    });

    after(() => {
        logFilesProcessor.removeTempLogFiles();
    });
});
