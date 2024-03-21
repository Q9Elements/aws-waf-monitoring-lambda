// ESLint is disabled for the below line because we use preinstalled aws-sdk from lambda container
// eslint-disable-next-line import/no-extraneous-dependencies
const {
    WAFV2Client,
    ListIPSetsCommand,
    GetIPSetCommand,
    UpdateIPSetCommand,
} = require('@aws-sdk/client-wafv2');
const _ = require('lodash');
const path = require('path');
const statisticsService = require('./statisticsService');
const constants = require('./constants');

/**
 * This function is used to create a new instance of WAFV2 client that will be later used in the dedicated
 * functions
 * @returns new instance of WAFV2 client
 */
function initialiseWAFV2Client() {
    return new WAFV2Client({ region: constants.AWS_REGION });
}

/**
 * This functions is used to retrieve a list of available AWS WAF IP Sets
 * @param {*} params - ipSetScope - specifies whether this is for an Amazon CloudFront distribution
 * or for a regional application
 * @returns list of retrieved IP sets or an empty array in case of error
 */
async function getListOfAWSWAFIPSets({ ipSetScope = 'REGIONAL' } = {}) {
    console.log('[WAFService] Getting a list of IPSets...');
    let ipSetsList;
    try {
        const wafv2Client = initialiseWAFV2Client();
        const params = {
            Scope: ipSetScope, /* required */
            Limit: 100,
        };
        const command = new ListIPSetsCommand(params);
        const response = await wafv2Client.send(command);

        ipSetsList = response.IPSets;
    } catch (err) {
        console.log('[WAFService] Error occured when getting a list of IPSets:', err);
        ipSetsList = [];
    }
    return ipSetsList;
}

/**
 * This functions is used to retrieve details of the specified IP Set
 * @param {*} params - ipSetScope - specifies whether this is for an Amazon CloudFront distribution;
 * ipSetName - name of the target IP set; ipSetId - id of the target IP set
 * @returns details of the specified IP Set
 */
async function getIPSet({ ipSetName, ipSetId, ipSetScope = 'REGIONAL' } = {}) {
    console.log('[WAFService] Getting IPSet details...');
    console.debug(`[WAFService] IPSet name: ${ipSetName}`);

    let ipSetDetails;
    try {
        const wafv2Client = initialiseWAFV2Client();
        const params = {
            Scope: ipSetScope, /* required */
            Name: ipSetName,
            Id: ipSetId,
        };
        const command = new GetIPSetCommand(params);
        const response = await wafv2Client.send(command);

        ipSetDetails = { IPSet: response.IPSet, LockToken: response.LockToken };
    } catch (err) {
        console.log('[WAFService] Error occured when getting IPSet details:', err);
        ipSetDetails = {};
    }
    return ipSetDetails;
}

/**
 * This functions is used to update details of the specified IP Set
 * @param {*} params - ipSetScope - specifies whether this is for an Amazon CloudFront distribution;
 * ipSetName - name of the target IP set;
 * ipSetId - id of the target IP set;
 * ipSetAddresses - see https://docs.aws.amazon.com/waf/latest/APIReference/API_UpdateIPSet.html;
 * ipSetDescription - IP set description;
 * ipSetLockToken - see https://docs.aws.amazon.com/waf/latest/APIReference/API_UpdateIPSet.html
 * @returns details of the specified IP Set
 */
async function updateIPSet({
    ipSetName,
    ipSetId,
    ipSetAddresses,
    ipSetDescription,
    ipSetLockToken,
    ipSetScope = 'REGIONAL',
} = {}) {
    console.log('[WAFService] Updating the specified IPSet...');
    let isUpdateSucceeded;
    try {
        const wafv2Client = initialiseWAFV2Client();
        const params = {
            Addresses: ipSetAddresses,
            Description: ipSetDescription,
            Id: ipSetId,
            LockToken: ipSetLockToken,
            Name: ipSetName,
            Scope: ipSetScope, /* required */
        };
        const command = new UpdateIPSetCommand(params);
        const response = await wafv2Client.send(command);

        console.debug('[WAFService] Update IP set operation response:', response);
        isUpdateSucceeded = true;
    } catch (err) {
        console.log('[WAFService] Error occured when updating IPSet details:', err);
        isUpdateSucceeded = false;
    }
    return isUpdateSucceeded;
}

/**
 * This function converts IP addresses from the retrieved IPSet to the expected by the updateIPSet
 * operation format - Array of IPs to be included in the IPSet.
 * @param {*} ipSetAddresses - list of IP addresses in the retrieved IPSet
 * @returns modified list of IPSet addresses
 */
function prepareExistingIPSetAddressesForUpdate(ipSetAddresses) {
    console.log(`[WAFService] Preparing IPSet addresses (${ipSetAddresses}) for update operation...`);
    const ipSetItemRegex = /\d{0,3}.\d{0,3}.\d{0,3}.\d{0,3}.*/g;
    if (_.isArray(ipSetAddresses))
        return ipSetAddresses;
    else if (_.isString(ipSetAddresses) && ipSetItemRegex.test(ipSetAddresses))
        return [ipSetAddresses];
    else
        return [];
}

/**
 * This function is used to add an IP address to blacklist based on the analysis
 * results
 * @param {*} ipAddress - IP address that should be added to blacklist
 * @returns result of operation
 */
async function addNewIPAddressToBlacklist(ipAddress) {
    console.log(`[WAFService] Adding a new IP address (${ipAddress}) to blacklist...`);
    const ipSetsList = await getListOfAWSWAFIPSets();

    if (_.isEmpty(ipSetsList)) {
        console.log('[WAFService] Cannot retrieve IPSets list, see details above');
        return false;
    } else {
        const tgtIPSet = ipSetsList
            .filter((ipSet) => ipSet.Name === constants.AWS_WAF_IPV4_BLACKLIST_NAME).pop();

        const tgtIpSetDetails = await getIPSet({
            ipSetId: tgtIPSet.Id,
            ipSetName: tgtIPSet.Name,
        });

        console.debug(`[WAFService] Target IP set addresses list before update: ${tgtIpSetDetails.IPSet.Addresses}`);
        const updatedIPSetAddresses = prepareExistingIPSetAddressesForUpdate(tgtIpSetDetails.IPSet.Addresses);
        updatedIPSetAddresses.push(`${ipAddress}/32`);

        const isUpdateSucceeded = await updateIPSet({
            ipSetName: tgtIpSetDetails.IPSet.Name,
            ipSetId: tgtIpSetDetails.IPSet.Id,
            ipSetAddresses: updatedIPSetAddresses,
            ipSetDescription: tgtIpSetDetails.IPSet.Description,
            ipSetLockToken: tgtIpSetDetails.LockToken,
        });

        if (isUpdateSucceeded) {
            console.log(`[WAFService] Successfully added ${ipAddress} to blacklist!`);
            return true;
        } else {
            console.log(`[WAFService] Error occured when adding ${ipAddress} to blacklist!`);
            return false;
        }
    }
}

/**
 * This function checks if the blacklisting time for the provide IP record was expired
 * @param {*} ipRecordDetails - details of the IP record that was taken from file with blacklisted IPs
 * @returns results of inspection
 */
function checkIfBlacklistingPeriodExpired(ipRecordDetails) {
    console.log(`[WAFService] Check if blacklisting period expired for IP ${ipRecordDetails.ip}...`);
    const currentDate = new Date();
    const blacklistingStartDate = new Date(ipRecordDetails.startDate);
    const timeDiffInHours = (currentDate.getTime() - blacklistingStartDate.getTime())
        / (1000 * 60 * 60);
    return timeDiffInHours > constants.MAX_TIME_FOR_BLACKLISTING_HOURS;
}

/**
 * This functions analyses list of IPSet addresses, detects addresses that are not listed in the
 * ${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME} file and adds missing IPs
 * to the file
 * @param {*} params - ipSetAddresses - list of current IPSet addresses, existingBlacklistedIPs - list
 * of blacklisted IPs that is stored in ${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}
 * @returns updated list of blacklisted IPs that will be stored in file on S3
 */
function addMissingIPsFromIPSetToFile({ ipSetAddresses, existingBlacklistedIPs } = {}) {
    console.log('[WAFService] Determining missing IPSet addresses that are not listed in file...');
    const finalBlacklistedIPs = [...existingBlacklistedIPs];
    const blacklistedIPsList = existingBlacklistedIPs.map((ipRecord) => ipRecord.ip);
    /**
     * Sample ipSetAddress - 192.168.0.101/32 before this operation
     */
    const normalisedIPSetAddresses = ipSetAddresses.map((ipAddress) => ipAddress.split('/')[0]);
    const missingIps = _.difference(normalisedIPSetAddresses, blacklistedIPsList);

    if (!_.isEmpty(missingIps)) {
        const currentDate = new Date();

        for (const ip of missingIps) {
            console.debug(`[WAFService] Adding missing IPSet address (${ip}) to the file...`);
            finalBlacklistedIPs.push({
                ip,
                reasonsForBlacklisting: [constants.REASONS_FOR_BLACKLISTING_IP.MALICIOUS_ACTIVITY],
                startDate: currentDate,
                ipDetails: {
                    country: constants.NEUTRAL_FLAG_FOR_SLACK_MESSAGE,
                    abuseIpDBInfo: `https://www.abuseipdb.com/check/${ip}`,
                    threatBookInfo: `https://threatbook.io/ip/${ip}`,
                    virusTotalInfo: `https://www.virustotal.com/gui/ip-address/${ip}/detection`,
                },
            });
        }
    } else {
        console.log('[WAFService] Not detected any missing IPSet addresses');
    }

    return finalBlacklistedIPs;
}

/**
 * This function reviews a list of blacklisted IP addresses and removes IP addresses
 * that were blacklisted for more than ${constants.MAX_TIME_FOR_BLACKLISTING_HOURS} from IP set.
 * Also, it adds IP addresses that were only in the remote IP set to the file with blacklisted IPs
 * that are stored on S3
 * @returns results of update operation
 */
async function makeBlacklistsUpToDate() {
    console.log('[WAFService] Making existing blacklists up to date...');
    const existingBlacklistedIPs = require(path.resolve(__dirname,
        `${constants.TEMP_DIR_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`));
    const ipSetsList = await getListOfAWSWAFIPSets();
    let updatedBlacklistedIPs = [...existingBlacklistedIPs];

    if (_.isEmpty(ipSetsList)) {
        console.log('[WAFService] Cannot retrieve IPSets list, see details above');
        return false;
    } else {
        const tgtIPSet = ipSetsList
            .filter((ipSet) => ipSet.Name === constants.AWS_WAF_IPV4_BLACKLIST_NAME).pop();

        const tgtIpSetDetails = await getIPSet({
            ipSetId: tgtIPSet.Id,
            ipSetName: tgtIPSet.Name,
        });

        console.debug(`[WAFService] Target IP set addresses list before update: ${tgtIpSetDetails.IPSet.Addresses}`);
        let updatedIPSetAddresses = prepareExistingIPSetAddressesForUpdate(tgtIpSetDetails.IPSet.Addresses);

        for (const ipRecord of existingBlacklistedIPs)
            if (checkIfBlacklistingPeriodExpired(ipRecord)) {
                updatedIPSetAddresses = updatedIPSetAddresses.filter((ipAddress) => !ipAddress.startsWith(ipRecord.ip));
                updatedBlacklistedIPs = updatedBlacklistedIPs.filter((blacklistedIP) => !blacklistedIP.ip === ipRecord.ip);
            }
        updatedBlacklistedIPs = addMissingIPsFromIPSetToFile({
            ipSetAddresses: updatedIPSetAddresses, existingBlacklistedIPs: updatedBlacklistedIPs,
        });

        const isUpdateSucceeded = await updateIPSet({
            ipSetName: tgtIpSetDetails.IPSet.Name,
            ipSetId: tgtIpSetDetails.IPSet.Id,
            ipSetAddresses: updatedIPSetAddresses,
            ipSetDescription: tgtIpSetDetails.IPSet.Description,
            ipSetLockToken: tgtIpSetDetails.LockToken,
        });

        if (isUpdateSucceeded) {
            statisticsService.rewriteBlacklistedIPsFileAfterSync(updatedBlacklistedIPs);
            console.log('[WAFService] Successfully updated blacklists!');
            return true;
        } else {
            console.log('[WAFService] Error occured when updating blacklists!');
            return false;
        }
    }
}

module.exports = {
    addNewIPAddressToBlacklist,
    checkIfBlacklistingPeriodExpired,
    makeBlacklistsUpToDate,
    addMissingIPsFromIPSetToFile,
};
