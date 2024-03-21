const fs = require('fs');
const path = require('path');
const _ = require('lodash');
const { expect } = require('chai');
const logFilesProcessor = require('../src/logFilesProcessor');
const wafService = require('../src/wafService');
const logger = require('../src/logger');
const constants = require('../src/constants');
const sampleBlacklistedIPsFilePath = path.resolve(__dirname, './sample-data/sampleBlacklistedIPs.json');
const tmpBlacklistedIPsFilePath = path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/sampleBlacklistedIPs.json`);
const sampleIPSetAddresses = ['10.10.10.10/32', '10.10.10.11/32'];

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

describe('WAF service tests', () => {
    before(async() => {
        logger.setUpLogger();
        logFilesProcessor.removeTempLogFiles();
        logFilesProcessor.prepareTempDirForLogFiles();
        createSampleBlacklistedIpsForTest();
    });

    describe('Check "addMissingIPsFromIPSetToFile" function', () => {
        it('Should ensure that "addMissingIPsFromIPSetToFile" works as expected (new IPs)', () => {
            const existingBlacklistedIPs = require(tmpBlacklistedIPsFilePath);
            const expectedLength = existingBlacklistedIPs.length + sampleIPSetAddresses.length;
            const updatedBlacklistedIPs = wafService.addMissingIPsFromIPSetToFile({
                ipSetAddresses: sampleIPSetAddresses,
                existingBlacklistedIPs,
            });
            expect(updatedBlacklistedIPs.length).to.equal(expectedLength);
            const newlyAddedToBlacklistIPs = _.differenceBy(updatedBlacklistedIPs, existingBlacklistedIPs, 'ip');
            expect(newlyAddedToBlacklistIPs.length).to.equal(2);
            for (const ipRecord of newlyAddedToBlacklistIPs) {
                expect(ipRecord.ipDetails.country).to.equal(constants.NEUTRAL_FLAG_FOR_SLACK_MESSAGE);
                expect(ipRecord).has.property('startDate');
                expect(ipRecord).has.property('reasonsForBlacklisting').and.to.be.an('array');
            }
        });

        it('Should ensure that "addMissingIPsFromIPSetToFile" works as expected (already listed IPs)', () => {
            const existingBlacklistedIPs = require(tmpBlacklistedIPsFilePath);
            const expectedLength = existingBlacklistedIPs.length;
            const updatedBlacklistedIPs = wafService.addMissingIPsFromIPSetToFile({
                ipSetAddresses: [`${existingBlacklistedIPs[0].ip}/32`, `${existingBlacklistedIPs[1].ip}/32`],
                existingBlacklistedIPs,
            });
            expect(updatedBlacklistedIPs.length).to.equal(expectedLength);
            const newlyAddedToBlacklistIPs = _.differenceBy(updatedBlacklistedIPs, existingBlacklistedIPs, 'ip');
            expect(newlyAddedToBlacklistIPs.length).to.equal(0);
        });
    });

    describe('Check "checkIfBlacklistingPeriodExpired" function', () => {
        let expiredDate, validDate;

        before(() => {
            expiredDate = new Date();
            expiredDate.setDate(expiredDate.getDate() - 3);
            validDate = new Date();
        });

        it('Should ensure that "checkIfBlacklistingPeriodExpired" works as expected (expired date)', async() => {
            const sampleIPRecord = require(tmpBlacklistedIPsFilePath)[0];
            sampleIPRecord.startDate = expiredDate.toISOString();
            const result = wafService.checkIfBlacklistingPeriodExpired(sampleIPRecord);
            expect(result).to.be.true;
        });

        it('Should ensure that "checkIfBlacklistingPeriodExpired" works as expected (valid date)', async() => {
            const sampleIPRecord = require(tmpBlacklistedIPsFilePath)[0];
            sampleIPRecord.startDate = validDate.toISOString();
            const result = wafService.checkIfBlacklistingPeriodExpired(sampleIPRecord);
            expect(result).to.be.false;
        });
    });

    after(() => {
        logFilesProcessor.removeTempLogFiles();
    });
});
