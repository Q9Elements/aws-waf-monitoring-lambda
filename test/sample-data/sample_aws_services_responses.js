const path = require('path');

const S3_FILES_LIST_RESPONSE = {
    Contents: [
        {
            LastModified: '2023-04-06T14:15:50.000Z',
            ETag: '"621503c373607d548b37cff8778d992c"',
            StorageClass: 'STANDARD',
            Key: '012345678911_waflogs_us-east-1_AWSWAFSecurityAutomations_20230406T1415Z_1e27a176.log.gz',
            Size: 391,
        },
        {
            LastModified: '2023-04-06T14:30:50.000Z',
            ETag: '"a2cecc36ab7c7fe3a71a273b9d45b1b5"',
            StorageClass: 'STANDARD',
            Key: '012345678911_waflogs_us-east-1_AWSWAFSecurityAutomations_20230406T1430Z_41a8f81d.log.gz',
            Size: 373,
        },
    ],
};

const S3_DIRECTORIES_LIST_RESPONSE = {
    IsTruncated: false,
    Contents: [],
    Name: 'aws-waf-logs-sample-bucket',
    Prefix: 'AWSLogs/012345678911/WAFLogs/us-east-1/AWSWAFSecurityAutomations/2023/04/06/14/',
    Delimiter: '/',
    MaxKeys: 1000,
    CommonPrefixes: [
        {
            Prefix: 'AWSLogs/012345678911/WAFLogs/us-east-1/AWSWAFSecurityAutomations/2023/04/06/14/10/',
        },
    ],
    KeyCount: 1,
};

const S3_RESPONSE_PUT_OBJECT = {
    ETag: '"6805f2cfc46c0f04559748bb039d69ae"',
    VersionId: 'pSKidl4pHBiNwukdbcPXAIs.sshFFOc0',
};

function generateS3GetObjectResponse(fileName) {
    const archiveData = Buffer.from(require('fs')
        .readFileSync(path.resolve(__dirname, `../aws-waf-logs-samples/${fileName}`)));
    return {
        AcceptRanges: '',
        ContentLength: archiveData.length,
        ContentType: 'application/octet-stream',
        ETag: '"6805f2cfc46c0f04559748bb039d69ae"',
        LastModified: new Date().toISOString(),
        Metadata: {},
        TagCount: 2,
        VersionId: 'null',
        Body: archiveData,
    };
}

module.exports = {
    S3_DIRECTORIES_LIST_RESPONSE,
    S3_FILES_LIST_RESPONSE,
    S3_RESPONSE_PUT_OBJECT,
    generateS3GetObjectResponse,
};
