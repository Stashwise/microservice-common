"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.HashingServiceImpl = void 0;
const bcrypt = __importStar(require("bcrypt"));
const crypto = __importStar(require("crypto"));
const uuid_1 = require("uuid");
const crypto_js_1 = require("crypto-js");
const date_fns_1 = require("date-fns");
const errors_1 = require("@/errors");
class HashingServiceImpl {
    constructor(env) {
        this.authenticate = (params, time) => {
            const tokenExpiresInADay = (0, date_fns_1.addMinutes)(new Date(), 15);
            const tokenExpiresInMonths = (0, date_fns_1.addHours)(new Date(), 1);
            const access_token = this.encryptDataWithCryptoJs(JSON.stringify({ ...params, time: tokenExpiresInADay, expiresAt: '15minutes' }));
            const refresh_token = this.encryptDataWithCryptoJs(JSON.stringify({ ...params, time: tokenExpiresInMonths, expiresAt: time ? time : '1hour' }));
            return { access_token, refresh_token };
        };
        this.decrytData = (message) => {
            const decipher = crypto.createDecipheriv("aes-128-cbc", Buffer.from(String(this.ENCRYPTIONKEY)).subarray(0, 16), Buffer.from(this.ENCRYPTIONIV, "hex"));
            let decryptedMessage = decipher.update(Buffer.from(message, "hex"));
            decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);
            return decryptedMessage.toString();
        };
        this.encryptData = (message) => {
            let result;
            try {
                const cipher = crypto.createCipheriv("aes-128-cbc", Buffer.from(String(this.ENCRYPTIONKEY)).subarray(0, 16), Buffer.from(this.ENCRYPTIONIV, "hex"));
                let encryptedMessage = cipher.update(message);
                encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
                result = encryptedMessage.toString("hex");
            }
            catch (error) {
                result = "";
            }
            return result;
        };
        this.encryptVfdSignature = (message) => {
            const encrypt = (0, crypto_js_1.SHA512)(message).toString();
            return encrypt;
        };
        this.encryptDataWithCryptoJs = (message) => {
            const encrypts = crypto_js_1.AES.encrypt(message, this.ENCRYPTIONKEY).toString();
            return encrypts;
        };
        this.cryptoSecret = env.CRYPTO_SECRET;
        this.timeStep = env.CRYPTO_TIME_STEP;
        this.otpLength = env.CRYPTO_OTP_LENGTH;
        this.hashAlgorithm = env.CRYPTO_HASH_ALGO;
        this.saltRound = Number(env.SALT_ROUND);
        this.ENCRYPTIONKEY = env.STASHWISE_ENCRYPTIONKEY;
        this.ENCRYPTIONIV = env.STASHWISE_ENCRYPTIONIV;
    }
    async genSalt(rounds) {
        return bcrypt.genSalt(rounds);
    }
    async generateHashString(data, salt = bcrypt.genSaltSync(this.saltRound)) {
        const hashed = await bcrypt.hash(data, salt);
        return hashed;
    }
    async compare(data, hash) {
        return bcrypt.compare(data, hash);
    }
    generateTOTP() {
        const currentTime = Math.floor(Date.now() / 1000);
        const counter = Math.floor(currentTime / this.timeStep);
        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeUInt32BE(counter, 4);
        const hmac = crypto
            .createHmac(this.hashAlgorithm, this.cryptoSecret)
            .update(counterBuffer)
            .digest();
        const offset = hmac[hmac.length - 1] & 0x0f;
        const otpBytes = new Uint8Array(hmac.buffer, hmac.byteOffset + offset, 4);
        const otpValue = new DataView(otpBytes.buffer, otpBytes.byteOffset, otpBytes.byteLength).getUint32(0, false) % Math.pow(10, this.otpLength);
        return otpValue.toString().padStart(this.otpLength, '0');
    }
    generateVerificationHash() {
        return (0, uuid_1.v4)();
    }
    generatePassword(length = 7) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * characters.length);
            result += characters.charAt(randomIndex);
        }
        return result;
    }
    async decryptDataWithCryptoJs(message) {
        const TIMEOUT_MS = 10;
        const controller = new AbortController();
        const { signal } = controller;
        const decryptionPromise = new Promise((resolve, reject) => {
            try {
                const decrypts = crypto_js_1.AES.decrypt(message, this.ENCRYPTIONKEY).toString(crypto_js_1.enc.Utf8);
                if (!decrypts) {
                    reject(new errors_1.UnAuthorizedException());
                }
                resolve(decrypts);
            }
            catch (error) {
                reject(new errors_1.UnAuthorizedException());
            }
        });
        const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
        try {
            const result = await Promise.race([
                decryptionPromise,
                new Promise((_, reject) => signal.addEventListener('abort', () => reject(new errors_1.UnAuthorizedException())))
            ]);
            return result;
        }
        catch (error) {
            if (error instanceof errors_1.UnAuthorizedException) {
                return '';
            }
            throw error;
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
}
exports.HashingServiceImpl = HashingServiceImpl;
