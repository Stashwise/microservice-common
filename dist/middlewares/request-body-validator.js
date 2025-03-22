"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RequestBodyValidatorMiddleware = void 0;
const http_status_codes_1 = require("http-status-codes");
const RequestBodyValidatorMiddleware = (validationSchema, type) => (req, res, next) => {
    const getType = {
        payload: req.body,
        params: req.params,
        query: req.query,
        headers: req.headers,
    };
    const options = { messages: { key: '{{key}} ' } };
    const data = getType[type];
    const validationResult = validationSchema.validate(data, options);
    if (!validationResult.error) {
        return next();
    }
    const { message } = validationResult.error.details[0];
    return res.status(http_status_codes_1.StatusCodes.UNPROCESSABLE_ENTITY).json({
        status: 'error',
        statusCode: http_status_codes_1.StatusCodes.UNPROCESSABLE_ENTITY,
        message: message.replace(/"/gi, ''),
    });
};
exports.RequestBodyValidatorMiddleware = RequestBodyValidatorMiddleware;
