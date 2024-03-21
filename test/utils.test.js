const _ = require('lodash');
const { expect } = require('chai');
const logger = require('../src/logger');
const utils = require('../src/utils');
let res;

describe('Utils tests', () => {
    before(() => logger.setUpLogger());

    describe('"prepareDateParameterForQuery" function checks', () => {
        it('Should ensure that "prepareDateParameterForQuery" function works correctly (with delimiter)', () => {
            res = utils.prepareDateParameterForQuery(_.random(0, 9));
            expect(res).to.match(/0[0-9]\//);
        });

        it('Should ensure that "prepareDateParameterForQuery" function works correctly (no delimiter)', () => {
            res = utils.prepareDateParameterForQuery(_.random(0, 9), false);
            expect(res).to.match(/0[0-9]/);
        });

        it('Should ensure that "prepareDateParameterForQuery" function works '
            + 'correctly (with delimiter, number > 9)', () => {
            res = utils.prepareDateParameterForQuery(_.random(10, 50));
            expect(res).to.match(/[1-9][0-9]/);
        });

        it('Should ensure that "formatStringForSlackMessage" function works correctly', () => {
            const maxNumberOfElements = 10;
            const expectedStrLength = Math.floor(3000 / maxNumberOfElements) - 40 + '[...rest of string]'.length;
            res = utils.formatStringForSlackMessage({ tgtStr: _.pad('test', 1000, 'test'), maxNumberOfElements });
            expect(res.length).to.equal(expectedStrLength);
            expect(res.endsWith('[...rest of string]')).to.be.true;
        });
    });
});
