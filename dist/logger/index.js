"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Logger = void 0;
const winston_1 = __importDefault(require("winston"));
const winston_daily_rotate_file_1 = __importDefault(require("winston-daily-rotate-file"));
const dayjs_1 = __importDefault(require("dayjs"));
const infoLogRotationTransport = new winston_daily_rotate_file_1.default({
    filename: './/logs//info',
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '80d',
    level: 'info',
    extension: '.log'
});
const errorLogRotationTransport = new winston_daily_rotate_file_1.default({
    filename: './/logs//error',
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '80d',
    level: 'error',
    extension: '.log'
});
class Logger {
    constructor(config) {
        this.logFormat = winston_1.default.format.combine(winston_1.default.format.errors({ stack: true }), winston_1.default.format.printf((info) => {
            const time = `${(0, dayjs_1.default)().format('YYYY-MM-DD, HH:mm:ss')}`;
            const { level, message, stack, code } = info;
            if (level == 'error') {
                return `[❌❌❌ ${level}] [${time}] ${code != null ? `[${code}] -> [${message}]` : message} ${code == null || code >= 500 ? `$[ERR_STACK] -> ${stack}` : ''}`;
            }
            return `[${time}] | [${level}] -> ${message}`;
        }), winston_1.default.format.json());
        const { level = 'info', serviceName, } = config;
        this.logger = winston_1.default.createLogger({
            level,
            format: this.logFormat,
            defaultMeta: { service: serviceName },
            transports: [
                infoLogRotationTransport,
                errorLogRotationTransport,
                new winston_1.default.transports.Console({
                    format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
                })
            ],
            exitOnError: false
        });
    }
    info(message, meta) {
        this.logger.info(message, meta);
    }
    error(message, error, meta) {
        this.logger.error(message, {
            ...(error && {
                error: {
                    name: error.name,
                    message: error.message,
                    stack: error.stack
                }
            }),
            ...meta
        });
    }
    warn(message, meta) {
        this.logger.warn(message, meta);
    }
    debug(message, meta) {
        this.logger.debug(message, meta);
    }
}
exports.Logger = Logger;
