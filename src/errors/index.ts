import { Response } from 'express';
import { StatusCodes } from 'http-status-codes';

export class HttpException extends Error {
  constructor(public readonly code: number, message: string) {
    super(message);
  }
}

export class InternalServerErrorException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.INTERNAL_SERVER_ERROR, customMessage ?? 'Internal Server Error');
  }
}

export class ServiceUnavailableException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.SERVICE_UNAVAILABLE, customMessage ?? 'Service Unavailable');
  }
}

export class ConflictException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.CONFLICT, customMessage ?? 'Conflict');
  }
}

export class BadException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.BAD_REQUEST, customMessage ?? 'Bad Request');
  }
}

export class ForbiddenException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.FORBIDDEN, customMessage ?? 'Forbidden');
  }
}

export class UnAuthorizedException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.UNAUTHORIZED, customMessage ?? 'UNAUTHORIZED');
  }
}

export class NotFoundException extends HttpException {
  constructor(customMessage?: string) {
    super(StatusCodes.NOT_FOUND, customMessage ?? 'Not Found');
  }
}

export const handleCustomError = (
  res: Response,
  error: any,
  statusCode: number
) => {
  return res.status(statusCode).json({
    status: 'error',
    statusCode: statusCode,
    message: error.message
  });
};
