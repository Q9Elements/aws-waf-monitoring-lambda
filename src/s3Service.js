const fs = require('fs');
// ESLint is disabled for the below line because we use preinstalled aws-sdk from lambda container
// eslint-disable-next-line import/no-extraneous-dependencies
const {
    S3Client,
    GetObjectCommand,
    PutObjectCommand,
    ListObjectsV2Command,
} = require('@aws-sdk/client-s3');
const path = require('path');
const utils = require('./utils');
const constants = require('./constants');

/**
 * This functions returnes a formatted string that is used in Prefix parameter of
 * S3 object query
 * @param {*} params - tgtDate - date that should be used (Date),
 * addDelimiterToMonth - adds '/' to the month parameter in output (true by default),
 * addDelimiterToDay - adds '/' to the day parameter in output (true by default),
 * addDelimiterToHour - adds '/' to the hour parameter in output (true by default)
 * @returns formatted string (e.g. 2023/03/22/16)
 */
function generateS3ObjectPrefixDatePart({
    tgtDate,
    addDelimiterToMonth = true,
    addDelimiterToDay = true,
    addDelimiterToHour = true,
} = {}) {
    return `${tgtDate.getFullYear()}/`
        + utils.prepareDateParameterForQuery(tgtDate.getUTCMonth() + 1, addDelimiterToMonth)
        + utils.prepareDateParameterForQuery(tgtDate.getUTCDate(), addDelimiterToDay)
        + utils.prepareDateParameterForQuery(tgtDate.getUTCHours(), addDelimiterToHour);
}

/**
 * This function creates object prefix for uploading logs processing results to the S3 bucket
 * where AWS WAF logs are stored
 * @returns object prefix for uploading object to S3 bucket
 */
function getObjectPrefixForUploadToS3() {
    console.log('[s3Service] Creating object prefix to query S3 bucket (upload lambda report)...');
    // example prefix
    // s3://aws-waf-logs-bucket/<FOLDER_NAME>/2023/03/22/16
    const currDate = new Date();
    const objectPrefix = `${constants.S3_UPLOAD_FOLDER_NAME}/`
        + generateS3ObjectPrefixDatePart({ tgtDate: currDate, addDelimiterToHour: false });
    console.log('[s3Service] Object prefix: ', objectPrefix);
    return objectPrefix;
}

/**
 * This function creates object prefix to query S3 bucket where AWS WAF logs are stored
 * @returns object prefix for a query to S3 bucket
 */
function getObjectPrefixForGetLogsS3Query() {
    console.log('[s3Service] Creating object prefix to query S3 bucket (get WAF logs)...');
    // example prefix
    // s3://aws-waf-logs-bucket/AWSLogs/<account_id>/WAFLogs/us-east-1/AWSWAFSecurityAutomations/2023/03/22/16
    const currDate = new Date();
    currDate.setHours(currDate.getHours() - 1);
    const objectPrefix = `AWSLogs/${constants.AWS_ACCOUNT_ID}/${constants.S3_AWS_WAF_LOGS_BUCKET_FOLDER_PREFIX}`
        + generateS3ObjectPrefixDatePart({ tgtDate: currDate });
    console.log('[s3Service] Object prefix: ', objectPrefix);
    return objectPrefix;
}

/**
 * This function creates object prefix to query S3 bucket where AWS WAF lambda reports are stored
 * @param {*} params - timeShiftHours - difference between current hour and target hour for which you would like to
 * get a report. For example, if you'd like to get a lambda report for the previous hour, you should pass
 * {timeShiftHours: -1}
 * @returns object prefix for a query to S3 bucket
 */
function getObjectPrefixForGetLambdaReportS3Query({ timeShiftHours = -1 } = {}) {
    console.log('[s3Service] Creating object prefix to query S3 bucket for retrieving lambda reports...');
    // example prefix
    // s3://aws-waf-logs-bucket/<FOLDER_NAME>/2023/03/22/16
    const currDate = new Date();
    currDate.setHours(currDate.getHours() + timeShiftHours);
    const objectPrefix = `${constants.S3_UPLOAD_FOLDER_NAME}/`
        + generateS3ObjectPrefixDatePart({ tgtDate: currDate });
    console.log('[s3Service] Object prefix: ', objectPrefix);
    return objectPrefix;
}

/**
 * This function is used to create a new instance of S3 client that will be later used in the dedicated
 * functions
 * @returns new instance of S3 client
 */
function initialiseS3Client() {
    return new S3Client({ region: constants.AWS_REGION });
}

/**
 * This function is used to upload the provided file to S3 bucket
 * @param {*} params - fileContent - content of the file that should be uploaded;
 * bucketName - name of the bucket where we want to upload file (default: constants.S3_AWS_WAF_LOGS_BUCKET_NAME);
 * fileKey - target object key
 * @returns results of upload
 */
async function uploadFileToS3Bucket({
    bucketName = constants.S3_AWS_WAF_LOGS_BUCKET_NAME,
    fileKey,
    fileContent,
} = {}) {
    try {
        console.log(`[s3Service] Uploading file (${fileKey}) to S3...`);
        // More details here: https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#putObject-property
        const params = {
            Body: fileContent,
            Bucket: bucketName,
            Key: fileKey,
        };
        const s3Client = initialiseS3Client();
        const command = new PutObjectCommand(params);

        await s3Client.send(command);
        console.log(`[s3Service] Successfully uploaded file (${params.Key}) to S3`);
        return true;
    } catch (err) {
        console.log('[s3Service] Error occured during uploading file to S3:', err);
        return false;
    }
}

/**
 * This function is used to save processed logs or statistics on S3. Logs are uploaded to the dedicated
 * folder with the following structure: <FOLDER_NAME>/<year>/<month>/<day>/<hour>/<fileName>
 * @param {*} params - fileName - name of file on a local filesystem that should be uploaded to S3
 * @returns results of upload
 */
async function sendProcessedDataToS3({ fileName = constants.OUTPUT_LOG_RECORDS_FILE_NAME } = {}) {
    if (constants.SEND_PROCESSED_DATA_TO_S3 === 'true') {
        try {
            const fileContent = fs.readFileSync(path
                .resolve(__dirname, `${constants.TEMP_DIR_NAME}/${fileName}`));
            console.log('[s3Service] Uploading processing results to S3...');
            await uploadFileToS3Bucket({
                fileKey: `${getObjectPrefixForUploadToS3()}/${fileName}`,
                fileContent,
            });
            console.log(`[s3Service] Successfully uploaded log records to S3: ${fileName}`);
            return true;
        } catch (err) {
            console.log('[s3Service] Error occured during uploading processed logs to S3:', err);
            return false;
        }
    } else {
        console.log('[s3Service] SEND_PROCESSED_DATA_TO_S3 env variable is set to "false", skipped this step');
        return true;
    }
}

/**
 * This function is used to save file with blacklisted IPs on S3. File is uploaded to the
 * constants.S3_UPLOAD_FOLDER_NAME/constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME
 * @param {*} params - fileName - name of file on a local filesystem that should be uploaded to S3
 * @returns results of upload
 */
async function sendIPsBlacklistToS3({ fileName = constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME } = {}) {
    if (constants.SEND_PROCESSED_DATA_TO_S3 === 'true') {
        try {
            const fileContent = fs.readFileSync(path
                .resolve(__dirname, `${constants.TEMP_DIR_NAME}/${fileName}`));
            console.log('[s3Service] Uploading file with blacklisted IPs to S3...');
            await uploadFileToS3Bucket({
                fileKey: `${constants.S3_UPLOAD_FOLDER_NAME}/${fileName}`,
                fileContent,
            });
            console.log(`[s3Service] Successfully uploaded file with blacklisted IPs to S3: ${fileName}`);
            return true;
        } catch (err) {
            console.log('[s3Service] Error occured during uploading file with blacklisted IPs to S3:', err);
            return false;
        }
    } else {
        console.log('[s3Service] SEND_PROCESSED_DATA_TO_S3 env variable is set to "false", skipped this step');
        return true;
    }
}

/**
 * This function retrieves a list of objects in S3 bucket using the specified parameters.
 * @param {*} params - bucketName - name of target S3 bucket, delimiter - delimiter for S3 query,
 * prefix - object prefix
 * @returns listObjectsV2 promise
 */
async function listS3BucketObjects({
    bucketName = constants.S3_AWS_WAF_LOGS_BUCKET_NAME,
    delimiter = '/',
    prefix = '',
} = {}) {
    console.log('[s3Service] Retrieving a list of S3 bucket objects');
    console.debug(`[s3Service] Bucket: ${bucketName}, delimiter: ${delimiter}, prefix: ${prefix}`);
    const s3Client = initialiseS3Client();
    // More details here: https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#listObjectsV2-property
    const params = {
        Bucket: bucketName, /* required */
        Delimiter: delimiter,
        Prefix: prefix,
    };
    const command = new ListObjectsV2Command(params);

    try {
        const response = await s3Client.send(command);
        return response;
    } catch (error) {
        console.debug('[s3Service] Error occured when listing objects in S3 bucket:', error);
        return '';
    }
}

/**
 * This function downloads an object from S3 bucket using specified parameters.
 * @param {*} params - bucketName - name of target S3 bucket, key - target object key
 * @returns getObject promise
 */
async function getObjectFromS3Bucket({
    bucketName = constants.S3_AWS_WAF_LOGS_BUCKET_NAME,
    key = '',
    transformResponseBodyToString = false,
} = {}) {
    console.log('[s3Service] Downloading an object from S3 bucket');
    console.debug(`[s3Service] Bucket: ${bucketName}, key: ${key}`);
    const s3Client = initialiseS3Client();
    const command = new GetObjectCommand({
        Bucket: bucketName,
        Key: key,
    });

    try {
        const response = await s3Client.send(command);
        if (transformResponseBodyToString)
            return response.Body.transformToString('utf-8');
        else
            return response.Body.transformToByteArray();
    } catch (error) {
        console.debug('[s3Service] Error occured when downloading object from S3:', error);
        return '';
    }
}

/**
 * This function is used to download file with information about blacklisted IPs from
 * S3 bucket and save it to the temporary folder
 * @param {*} params - bucketName - name of target S3 bucket, key - target object key
 */
async function retrieveFileWithBlacklistedIPsFromS3({
    bucketName = constants.S3_AWS_WAF_LOGS_BUCKET_NAME,
    key = `${constants.S3_UPLOAD_FOLDER_NAME}/${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`,
} = {}) {
    console.log('[s3Service] Downloading file with the blacklisted IPs from S3 bucket');
    console.debug(`[s3Service] Bucket: ${bucketName}, key: ${key}`);
    try {
        const response = await getObjectFromS3Bucket({ bucketName, key, transformResponseBodyToString: true });
        fs.writeFileSync(path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/`
            + `${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`), response);
    } catch (err) {
        console.log('[s3Service] Error occured when retrieving blacklist from S3:', err);
        console.log('[s3Service] Creating an empty file to prevent errors...');
        fs.writeFileSync(path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/`
            + `${constants.OUTPUT_BLACKLISTED_IPS_FILE_NAME}`), JSON.stringify([]));
    }
}

module.exports = {
    sendProcessedDataToS3,
    sendIPsBlacklistToS3,
    getObjectPrefixForGetLogsS3Query,
    listS3BucketObjects,
    getObjectFromS3Bucket,
    getObjectPrefixForGetLambdaReportS3Query,
    retrieveFileWithBlacklistedIPsFromS3,
};
