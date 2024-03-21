const fs = require('fs');
const path = require('path');
const { expect } = require('chai');
const logFilesProcessor = require('../src/logFilesProcessor');
const logsRecordsProcessor = require('../src/logRecordsProcessor');
const analyticsService = require('../src/analyticsService');
const logger = require('../src/logger');
const constants = require('../src/constants');
const sampleBlacklistedIPsFilePath = path.resolve(__dirname, './sample-data/sampleBlacklistedIPs.json');
const tmpBlacklistedIPsFilePath = path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/sampleBlacklistedIPs.json`);

/**
 * This function is used to modify sample blacklisted IPs and set "startDate" parameter
 * for two of them to the current date. Then, modified records are saved to the file
 */
function createSampleBlacklistedIpsForTest() {
    const sampleBlacklistedIPs = require(sampleBlacklistedIPsFilePath);
    const date = new Date();

    sampleBlacklistedIPs[0].startDate = date;
    sampleBlacklistedIPs[1].startDate = date;

    fs.writeFileSync(tmpBlacklistedIPsFilePath, JSON.stringify(sampleBlacklistedIPs));
}

describe('Analytics service tests', () => {
    before(async() => {
        logger.setUpLogger();
        logFilesProcessor.removeTempLogFiles();
        logFilesProcessor.prepareTempDirForLogFiles();
        await logFilesProcessor.getAWSWAFLogsFromS3();
        await logsRecordsProcessor.extractAndProcessWAFLogRecords();
        createSampleBlacklistedIpsForTest();
    });

    it('Should ensure that "getBlacklistedDuringPreviousDayIPs" works as expected', async() => {
        const recentlyBlacklistedIPs = await analyticsService.getBlacklistedDuringPreviousDayIPs({
            blacklistFilePath: tmpBlacklistedIPsFilePath,
        });
        expect(recentlyBlacklistedIPs.length).to.equal(2);
    });

    after(() => {
        logFilesProcessor.removeTempLogFiles();
    });
});
