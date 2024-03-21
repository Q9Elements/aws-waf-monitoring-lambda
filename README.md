# AWS WAF monitoring lambda

Here you can find source code of a custom AWS Lambda function that can be used to monitor
AWS WAF findings and send updates to a dedicated Slack channel.

## Prerequisites

* Node.JS v.18.x.x (recommended - _18.15.0_)
* Any IDE that can be used to work with the function code (_VSCode_, _WebStorm_)
* Create a copy of _sample_env_file.txt_ file and name it _.env_. Add required env variables.
**NOTE**: avoid using real Slack webhook url in order to not submit a large number of test
messages to the chat during the local testing. 

## Git flow for the repository

Below are steps that should be followed by all contributors when they are going to add changes to this
lambda function source code.

1. Checkout to the _master_ branch of this repository.
2. Pull the latest updates from remote _aws-waf-monitoring-lambda_ repository.
3. Create a new branch using the following naming convention `fix|feat/xxxxxx`. Prefix
_fix_ should be used when you're going to update existing functionality and _feat_ is used when you're
planning to add a new feature.
4. Add your changes.
5. Before commiting your changes, make sure that your working branch is up to date with the latest _master_.
6. Commit changes. Please choose meaningful short messages that help to identify the added changes. Several
examples: _IP Blacklisting: updated function for retrieving blacklisted IPs_, _- fixed issues with axios package_.
7. Push your changes to the remote repository and open a new _pull request_ to the _master_ branch. Request review from the maintainers.

## How to generate documentation for this lambda function

1. Pull remote repository to your local machine.
2. Install modules using `npm i` command.
3. Run `npm run generate-documentation`. Documentation will be available in the _docs_ folder.

## How to generate a new prod version of lambda function

Please note that an alternative way is to create a CodeBuild that will deploy this function using
the Serverless framework.

1. Run `npm run build` command.
2. Remove any test files that were used during development.
3. Create a _zip_ archive from _aws-waf-monitoring-lambda_ folder.
4. Update lambda function code using generated _zip_ archive.

## How to run tests to verify that all functions work as expected

1. Create _.env_ file using _sample_env_file.txt_.
2. Install modules using `npm i` command.
3. Run tests using `npm test` or `./node_modules/.bin/mocha --config ./test/config.mocharc.json ./test/` command.
There should not be any failed tests. 
