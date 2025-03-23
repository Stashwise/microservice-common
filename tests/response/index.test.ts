import { expect } from 'chai';
import sinon from 'sinon';
import { Response } from 'express';
import { HashingServiceImpl } from '../../src/auth';
import { ApiResponse } from '../../src/response';
import { BadException, ConflictException, ForbiddenException, NotFoundException, UnAuthorizedException } from '../../src/errors';
import { StatusCodes } from 'http-status-codes';
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

describe('API-RESPONSE HANDLERS', () => {
  let res: Response;
  let mockJson: sinon.SinonStub;
  let mockStatus: sinon.SinonStub;
  let mockSetHeader: sinon.SinonStub;
  let encryptStub: sinon.SinonStub;
  let hashingService = new HashingServiceImpl(mockEnv)

  beforeEach(() => {
    mockJson = sinon.stub();
    mockStatus = sinon.stub().returns({ json: mockJson });
    mockSetHeader = sinon.stub();

    res = {
      status: mockStatus,
      setHeader: mockSetHeader,
    } as unknown as Response;

    // Stub the encryptData function in the hashingService
    encryptStub = sinon.stub(hashingService, 'encryptData').callsFake((data) => `encrypted-${data}`);
  });

  describe('error handling', () => {
    it('should return a ConflictException error response', () => {
      const err = new ConflictException('Conflict occurred');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.CONFLICT)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.CONFLICT,
        message: 'Conflict occurred',
      })).to.be.true;
    });

    it('should return a BadException error response', () => {
      const err = new BadException('Bad request');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.BAD_REQUEST)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.BAD_REQUEST,
        message: 'Bad request',
      })).to.be.true;
    });

    it('should return a ForbiddenException error response', () => {
      const err = new ForbiddenException('Access forbidden');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.FORBIDDEN)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.FORBIDDEN,
        message: 'Access forbidden',
      })).to.be.true;
    });

    it('should return an UnAuthorizedException error response', () => {
      const err = new UnAuthorizedException('Unauthorized access');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.UNAUTHORIZED)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.UNAUTHORIZED,
        message: 'Unauthorized access',
      })).to.be.true;
    });

    it('should return a NotFoundException error response', () => {
      const err = new NotFoundException('Not found');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.NOT_FOUND)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.NOT_FOUND,
        message: 'Not found',
      })).to.be.true;
    });

    it('should return a generic error response for unknown errors', () => {
      const err = new Error('Unknown error');
      ApiResponse(res, err, err.message, hashingService);

      expect(mockStatus.calledWith(StatusCodes.INTERNAL_SERVER_ERROR)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'error',
        code: StatusCodes.INTERNAL_SERVER_ERROR,
        message: 'Unknown error',
      })).to.be.true;
    });
  });

  describe('success handling', () => {
    it('should return a success response with default message and no data', () => {
      ApiResponse(res, null, undefined, hashingService);

      expect(mockStatus.calledWith(StatusCodes.OK)).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'success',
        code: StatusCodes.OK,
        message: 'Successful',
        data: null,
      })).to.be.true;
    });

    it('should return a success response with custom message and data', () => {
      const customMessage = 'Operation completed';
      const customData = { key: 'value' };
      ApiResponse(res, null, customMessage, hashingService, StatusCodes.OK, customData);

      expect(mockStatus.calledWith(StatusCodes.OK)).to.be.true;
      expect(encryptStub.calledOnceWith(JSON.stringify(customData))).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'success',
        code: StatusCodes.OK,
        message: customMessage,
        data: 'encrypted-{"key":value,"name":"test"}',
      })).to.be.true;
    });

    it('should handle the hash header and remove it from err object', () => {
      const errWithHash = { hash: '12345' };
      ApiResponse(res, errWithHash, undefined, hashingService);

      expect(mockSetHeader.calledWith('hash-id-key', '12345')).to.be.true;
      expect(encryptStub.calledOnceWith(JSON.stringify({}))).to.be.true;
      expect(mockJson.calledWithMatch({
        status: 'success',
        code: StatusCodes.OK,
        message: 'Successful',
        data: 'encrypted-{"":"test"}',
      })).to.be.true;
    });
  });
});