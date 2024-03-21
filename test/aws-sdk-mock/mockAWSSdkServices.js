const { mockClient } = require('aws-sdk-client-mock');
const {
    S3Client,
    GetObjectCommand,
    PutObjectCommand,
    ListObjectsV2Command,
} = require('@aws-sdk/client-s3');
const _ = require('lodash');
const sampleAWSServicesResponses = require('../sample-data/sample_aws_services_responses');

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

/**
 * Up to date format of IP blacklist records can be reviewed in the
 * aws-waf-monitoring-lambda/src/statisticsService.js file
 */
const sampleIPBlacklistRecord = {
    ip: '192.168.0.1',
    reasonsForBlacklisting: ['XSS attack attempt'],
    startDate: new Date(),
};

/**
 * This function is used to mock required S3 services during run of Mocha test suites.
 * It is later used by the tests runner to mock all the methods before launching test
 * suites
 */
function mockS3Client() {
    console.log('[mockAWSSdkServices] Creating mock S3 client...');
    const s3Mock = mockClient(S3Client);
    // S3 listObjectsV2 mock - return a list of files or folders
    s3Mock.on(ListObjectsV2Command)
        .callsFake((input) => {
            console.log('[mockAWSSdkServices]*S3:mock:listObjectsV2*');
            console.log('[mockAWSSdkServices][S3:mock:listObjectsV2] Params:', input);
            if (input.Prefix.match(/^.*\/[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/[0-9]{2}\/$/)) {
                sampleAWSServicesResponses.S3_DIRECTORIES_LIST_RESPONSE.Prefix = input.Prefix;
                return sampleAWSServicesResponses.S3_DIRECTORIES_LIST_RESPONSE;
            } else
                return sampleAWSServicesResponses.S3_FILES_LIST_RESPONSE;
        });
    // S3 getObject mock
    s3Mock.on(GetObjectCommand)
        .callsFake((input) => {
            const response = sampleAWSServicesResponses.generateS3GetObjectResponse(input.Key);
            return _.merge(
                _.omit(response, ['Body']),
                {
                    Body: {
                        transformToByteArray: () => response.Body,
                    },
                });
        });
    // S3 putObject mock - return a result of object upload
    s3Mock.on(PutObjectCommand)
        .callsFake((input) => {
            console.log('[mockAWSSdkServices]*S3:mock:putObject*');
            console.log('[mockAWSSdkServices][S3:mock:putObject] Params:', input);
            console.log('[mockAWSSdkServices][S3:mock:putObject] Params body string:', input.Body.toString());
            const receivedJSON = input.Body.toString();
            try {
                const obj = JSON.parse(receivedJSON);
                if (Object.keys(obj).includes(_.sample(outputFileSections)))
                    return sampleAWSServicesResponses.S3_RESPONSE_PUT_OBJECT;
                else if (Object.keys(obj[0]).includes(_.sample(Object.keys(sampleIPBlacklistRecord))))
                    return sampleAWSServicesResponses.S3_RESPONSE_PUT_OBJECT;
                else
                    return 'Upload failed. Invalid Data';
            } catch (err) {
                console.log('[mockAWSSdkServices][S3:mock:putObject] Error occured:', err);
                return 'Upload failed. Invalid Data';
            }
        });
}

(() => {
    mockS3Client({
        S3Client,
        GetObjectCommand,
        PutObjectCommand,
        ListObjectsV2Command,
    });
})();
