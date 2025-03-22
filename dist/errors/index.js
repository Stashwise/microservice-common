"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handleCustomError = exports.NotFoundException = exports.UnAuthorizedException = exports.ForbiddenException = exports.BadException = exports.ConflictException = exports.ServiceUnavailableException = exports.InternalServerErrorException = exports.HttpException = void 0;
const http_status_codes_1 = require("http-status-codes");
class HttpException extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
exports.HttpException = HttpException;
class InternalServerErrorException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.INTERNAL_SERVER_ERROR, customMessage ?? 'Internal Server Error');
    }
}
exports.InternalServerErrorException = InternalServerErrorException;
class ServiceUnavailableException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.SERVICE_UNAVAILABLE, customMessage ?? 'Service Unavailable');
    }
}
exports.ServiceUnavailableException = ServiceUnavailableException;
class ConflictException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.CONFLICT, customMessage ?? 'Conflict');
    }
}
exports.ConflictException = ConflictException;
class BadException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.BAD_REQUEST, customMessage ?? 'Bad Request');
    }
}
exports.BadException = BadException;
class ForbiddenException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.FORBIDDEN, customMessage ?? 'Forbidden');
    }
}
exports.ForbiddenException = ForbiddenException;
class UnAuthorizedException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.UNAUTHORIZED, customMessage ?? 'UNAUTHORIZED');
    }
}
exports.UnAuthorizedException = UnAuthorizedException;
class NotFoundException extends HttpException {
    constructor(customMessage) {
        super(http_status_codes_1.StatusCodes.NOT_FOUND, customMessage ?? 'Not Found');
    }
}
exports.NotFoundException = NotFoundException;
const handleCustomError = (res, error, statusCode) => {
    return res.status(statusCode).json({
        status: 'error',
        statusCode: statusCode,
        message: error.message
    });
};
exports.handleCustomError = handleCustomError;
