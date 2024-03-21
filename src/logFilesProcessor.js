const zlib = require('zlib');
const path = require('path');
const fs = require('fs');
const constants = require('./constants');
const s3Service = require('./s3Service');
const utils = require('./utils');

/**
 * This function is used to unzip the downloaded file with logs and
 * save them in JSON format.
 * @param {*} fileName - logs file name
 * @param {*} fileContent - logs file content
 * @returns Promise
 */
async function prepareLogsForProcessing({ fileName, fileContent }) {
    // Write data from S3 to *.gz archive
    console.log(`[logFilesProcessor] Preparing log file ${fileName} for processing, ${typeof fileContent}`);
    const unzip = zlib.createUnzip();
    const gzipFileName = path.resolve(__dirname, `${constants.TEMP_DIR_NAME}/${fileName}`);
    fs.writeFileSync(gzipFileName, fileContent);
    // Extract log file from the archive
    const input = fs.createReadStream(gzipFileName);
    const output = fs.createWriteStream(gzipFileName.replace('.gz', ''));
    return new Promise((resolve) => {
        input.pipe(unzip).pipe(output)
            .on('finish', () => {
                console.log(`[logFilesProcessor] Successfully decompressed log file ${fileName}`);
                input.close();
                output.close();
                resolve();
            });
    });
}

/**
 * This function retrieves logs from S3 and launches processing. NOTE: lambda function
 * will process logs that were generated during the previous hour.
 */
async function getAWSWAFLogsFromS3() {
    try {
        console.log('[logFilesProcessor] Retrieving AWS WAF logs from S3');
        const availableLogFolders = await s3Service.listS3BucketObjects({
            prefix: s3Service.getObjectPrefixForGetLogsS3Query(),
        });
        let availableLogFiles;
        console.log('[logFilesProcessor] Retrieved log folders: ', availableLogFolders);
        for (const prefixItem of availableLogFolders.CommonPrefixes) {
            availableLogFiles = await s3Service.listS3BucketObjects({
                prefix: prefixItem.Prefix,
            });
            console.log('[logFilesProcessor] Retrieved log files for folder:', availableLogFiles);
            for (const file of availableLogFiles.Contents) {
                const logFileData = await s3Service.getObjectFromS3Bucket({
                    key: file.Key,
                });
                console.debug('[logFilesProcessor] Data:', logFileData);
                await prepareLogsForProcessing({
                    fileName: file.Key.split('/').pop(),
                    fileContent: logFileData,
                });
            }
        }
    } catch (err) {
        console.error('[logFilesProcessor] Error occurred during retrieving AWS WAF logs from S3');
        console.error(err);
    }
}

/**
 * This function prepares folder for temp files that are created during logs processing
 */
function prepareTempDirForLogFiles() {
    console.log('[logFilesProcessor] Creating dir for temp files...');
    utils.prepareTempDir(constants.TEMP_DIR_NAME);
}

/**
 * This function will remove temp files. We need to remove temp files from /tmp lambda storage
 * manually because it is not an automated process.
 */
function removeTempLogFiles() {
    console.log('[logFilesProcessor] Removing temp files...');
    utils.removeTempFiles(constants.TEMP_DIR_NAME);
}

module.exports = {
    getAWSWAFLogsFromS3,
    prepareTempDirForLogFiles,
    removeTempLogFiles,
};
