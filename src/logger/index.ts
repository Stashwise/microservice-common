import winston, { Logger as WinstonLogger } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import dayjs from 'dayjs';

export interface LoggerConfig {
    level?: string;
    serviceName: string;
    includeTimestamp?: boolean;
}

const infoLogRotationTransport = new DailyRotateFile({
    filename: './/logs//info',
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '80d',
    level: 'info',
    extension: '.log'
});
  
const errorLogRotationTransport = new DailyRotateFile({
    filename: './/logs//error',
    zippedArchive: true,
    maxSize: '10m',
    maxFiles: '80d',
    level: 'error',
    extension: '.log'
});

export class Logger {
    private logger: WinstonLogger;
    private logFormat = winston.format.combine(
        winston.format.errors({ stack: true }),
        winston.format.printf((info: any) => {
          const time = `${dayjs().format('YYYY-MM-DD, HH:mm:ss')}`;
      
          const { level, message, stack, code } = info;
      
          if (level == 'error') {
            return `[❌❌❌ ${level}] [${time}] ${code != null ? `[${code}] -> [${message}]` : message
            } ${code == null || code >= 500 ? `$[ERR_STACK] -> ${stack}` : ''}`;
          }
      
          return `[${time}] | [${level}] -> ${message}`;
        }),
        winston.format.json()
    );
  
    constructor(config: LoggerConfig) {
      const { 
        level = 'info', 
        serviceName, 
      } = config;
  
      this.logger = winston.createLogger({
        level,
        format: this.logFormat,
        defaultMeta: { service: serviceName },
        transports: [
            infoLogRotationTransport,
            errorLogRotationTransport,
            new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            })
        ],
        exitOnError: false
      });
    }
  
    info(message: string, meta?: Record<string, any>): void {
      this.logger.info(message, meta);
    }
  
    error(message: string, error?: Error, meta?: Record<string, any>): void {
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
  
    warn(message: string, meta?: Record<string, any>): void {
      this.logger.warn(message, meta);
    }
  
    debug(message: string, meta?: Record<string, any>): void {
      this.logger.debug(message, meta);
    }
}