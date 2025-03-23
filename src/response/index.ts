import { Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import {
  BadException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  ServiceUnavailableException,
  UnAuthorizedException,
} from '../errors';


const sendResponse = (
  res: Response,
  status: 'success' | 'error',
  code: number,
  message: string,
  data?: any
) => {
  return res.status(code).json({
    status,
    code,
    message,
    data,
  });
};

const error = (res: Response, error: any) => {
  if (error instanceof ServiceUnavailableException) {
    return sendResponse(res, 'error', StatusCodes.INTERNAL_SERVER_ERROR, error.message);
  }
  if (error instanceof ConflictException) {
    return sendResponse(res, 'error', StatusCodes.CONFLICT, error.message);
  }
  if (error instanceof BadException) {
    return sendResponse(res, 'error', StatusCodes.BAD_REQUEST, error.message);
  }
  if (error instanceof ForbiddenException) {
    return sendResponse(res, 'error', StatusCodes.FORBIDDEN, error.message);
  }
  if (error instanceof UnAuthorizedException) {
    return sendResponse(res, 'error', StatusCodes.UNAUTHORIZED, error.message);
  }
  if (error instanceof NotFoundException) {
    return sendResponse(res, 'error', StatusCodes.NOT_FOUND, error.message);
  }
  return sendResponse(
    res,
    'error',
    StatusCodes.INTERNAL_SERVER_ERROR,
    error.message
  );
};

const success = (res: Response, code: number, message: string, data?: any) => {
  return sendResponse(res, 'success', code, message, data);
};

export const ApiResponse = (
  res: Response,
  err: any,
  message = 'Successful',
  hashingService: any,
  code?: number,
  data?: any,
  encrypt = true
) => {
  if (err instanceof Error) {
    return error(res, err);
  }
  if (err && err.hash && !(err instanceof Error)) {
    res.setHeader('hash-id-key', err.hash);
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //@ts-ignore
    delete err.hash;
  }
  const encryptedData = hashingService.encryptData(JSON.stringify(data ?? err))
  
  return success(res, code ?? StatusCodes.OK, message, encrypt ? encryptedData : (data ?? err));
};
