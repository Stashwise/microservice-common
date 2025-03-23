import { expect } from 'chai';
import sinon from 'sinon';
import { HashingServiceImpl } from '../../src/auth';
import { IHash } from '../../src/interface';

// Mock environment variables
const mockEnv: IHash = {
    CRYPTO_SECRET: 'test_secret',
    CRYPTO_TIME_STEP: 30,
    CRYPTO_OTP_LENGTH: 6,
    CRYPTO_HASH_ALGO: 'sha256',
    SALT_ROUND: 10,
    STASHWISE_ENCRYPTIONKEY: 'SASSUkIdBegrbwN_9mSeMsQQ45A',
    STASHWISE_ENCRYPTIONIV: '76d7c69d097c5689fd0622c33433b5de'
};

describe('HashingServiceImpl', () => {
    let hashingService: HashingServiceImpl;

    beforeEach(() => {
        hashingService = new HashingServiceImpl(mockEnv);
    });

    afterEach(() => {
        sinon.restore();
    });

    it('should generate a TOTP', () => {
        const totp = hashingService.generateTOTP();
        expect(totp).to.be.a('string').with.length(6);
    });

    it('should generate a verification hash', () => {
        const uuid = hashingService.generateVerificationHash();
        expect(uuid).to.be.a('string').with.length.greaterThan(0);
    });

    it('should generate a random password', () => {
        const password = hashingService.generatePassword(8);
        expect(password).to.be.a('string').with.length(8);
    });

    it('should encrypt data with crypto', () => {
        const encryptedData = hashingService.encryptData('test_message');
        expect(encryptedData).to.be.a('string').with.length.greaterThan(0);
    });

    it('should decrypt data with crypto', () => {
        const encryptedData = hashingService.encryptData('test_message');
        const decryptedData = hashingService.decrytData(encryptedData);
        expect(decryptedData).to.equal('test_message');
    });

    it('should encrypt data with CryptoJS', () => {
        const encryptedData = hashingService.encryptDataWithCryptoJs('test_message');
        expect(encryptedData).to.be.a('string').with.length.greaterThan(0);
    });

    it('should decrypt data with CryptoJS', async () => {
        const encryptedData = hashingService.encryptDataWithCryptoJs('test_message');
        const decryptedData = await hashingService.decryptDataWithCryptoJs(encryptedData);
        expect(decryptedData).to.equal('test_message');
    });

    it('should authenticate and return tokens', () => {
        const params = { user: 'test_user' };
        const tokens = hashingService.authenticate(params);
        expect(tokens).to.have.property('access_token');
        expect(tokens).to.have.property('refresh_token');
    });
});
