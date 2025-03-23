import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { AES, enc, SHA512 } from "crypto-js";
import { addHours, addMinutes } from 'date-fns';
import { AuthSigning, IHash } from "../interface";
import { UnAuthorizedException } from "../errors";

export interface HashingService {
    generateHashString(data: string, salt?: string): Promise<string>;
    compare(data: string, hash: string): Promise<boolean>;
    genSalt(rounds: number): Promise<string>;
    generateVerificationHash(): string;
    generateTOTP(): string;
    generatePassword(length: number): string;
    decrytData(data: string): string;
    encryptData(data: string): string;
    encryptDataWithCryptoJs(data: string): string;
    encryptVfdSignature(data: string): string;
    decryptDataWithCryptoJs(data: string): Promise<string>;
    authenticate(data: any, time?: string): AuthSigning;
}

export class HashingServiceImpl implements HashingService {
    private readonly cryptoSecret: string;
    private readonly timeStep: number;
    private readonly otpLength: number;
    private readonly hashAlgorithm: string;
    private readonly saltRound: number;
    private readonly ENCRYPTIONKEY: string;
    private readonly ENCRYPTIONIV: string;

    constructor(env: IHash) {
        this.cryptoSecret = env.CRYPTO_SECRET;
        this.timeStep = env.CRYPTO_TIME_STEP;
        this.otpLength = env.CRYPTO_OTP_LENGTH;
        this.hashAlgorithm = env.CRYPTO_HASH_ALGO;
        this.saltRound = Number(env.SALT_ROUND);
        this.ENCRYPTIONKEY = env.STASHWISE_ENCRYPTIONKEY;
        this.ENCRYPTIONIV = env.STASHWISE_ENCRYPTIONIV;
    }
    
    public async genSalt(rounds: number): Promise<string> {
      return bcrypt.genSalt(rounds);
    }
  
  
    public async generateHashString(
      data: string,
      salt = bcrypt.genSaltSync(this.saltRound)
    ): Promise<string> {
      const hashed = await bcrypt.hash(data, salt);
      return hashed;
    }
  
    public async compare(data: string, hash: string): Promise<boolean> {
      return bcrypt.compare(data, hash);
    }
  
    public generateTOTP(): string {
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
  
      const otpValue =
        new DataView(
          otpBytes.buffer,
          otpBytes.byteOffset,
          otpBytes.byteLength
        ).getUint32(0, false) % Math.pow(10, this.otpLength);
  
      return otpValue.toString().padStart(this.otpLength, '0');
    }
  
    public generateVerificationHash(): string {
      return uuidv4();
    }
  
    public generatePassword(length = 7) {
      const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let result = '';
      
      for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters.charAt(randomIndex);
      }
      return result;
    }
  
    public authenticate = (params: any, time?: string): AuthSigning => {
      const tokenExpiresInADay = addMinutes(new Date(), 15);
      const tokenExpiresInMonths = addHours(new Date(), 1);
      const access_token = this.encryptDataWithCryptoJs(
        JSON.stringify({ ...params, time: tokenExpiresInADay, expiresAt: '15minutes' }),
      );
      const refresh_token = this.encryptDataWithCryptoJs(
        JSON.stringify({ ...params, time: tokenExpiresInMonths, expiresAt: time ? time : '1hour' }),
      );
      return { access_token, refresh_token };
    };
  
    public decrytData = (message: string): string => {
      const decipher = crypto.createDecipheriv(
        "aes-128-cbc",
        Buffer.from(String(this.ENCRYPTIONKEY)).subarray(0, 16),
        Buffer.from(this.ENCRYPTIONIV as string, "hex")
      );
      let decryptedMessage = decipher.update(Buffer.from(message, "hex"));
      decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);
      return decryptedMessage.toString();
    };
    
    public encryptData = (message: string) => {
      let result;
      try {
        const cipher = crypto.createCipheriv(
          "aes-128-cbc",
          Buffer.from(String(this.ENCRYPTIONKEY)).subarray(0, 16),
          Buffer.from(this.ENCRYPTIONIV as string, "hex")
        );
        let encryptedMessage = cipher.update(message);
        encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);
        result = encryptedMessage.toString("hex");
      } catch (error) {
        result = "";
      }
      return result;
    };
  
    public encryptVfdSignature = (message: string) => {
      const encrypt = SHA512(message).toString()
  
      return encrypt;
    }
  
    public encryptDataWithCryptoJs = (message: string) => {
      const encrypts = AES.encrypt(message, this.ENCRYPTIONKEY).toString();
      return encrypts;
    };
  
    public async decryptDataWithCryptoJs(message: string): Promise<string> {
      const TIMEOUT_MS = 10;
      
      const controller = new AbortController();
      const { signal } = controller;
    
      // Promise for decryption logic
      const decryptionPromise = new Promise<string>((resolve, reject) => {
        try {
          // Simulate asynchronous decryption (e.g., if your logic were async)
          const decrypts = AES.decrypt(message, this.ENCRYPTIONKEY).toString(enc.Utf8);
          if (!decrypts) {
            reject(new UnAuthorizedException());
          }
          resolve(decrypts); // Resolve if decryption succeeds
        } catch (error) {
          reject(new UnAuthorizedException());
        }
      });
    
      // Timeout handling via AbortController
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
    
      try {
        // Return the decryption result, race between timeout and decryption
        const result = await Promise.race([
          decryptionPromise,
          new Promise<string>((_, reject) =>
            signal.addEventListener('abort', () => reject(new UnAuthorizedException()))
          )
        ]);
    
        return result;
      } catch (error) {
        if (error instanceof UnAuthorizedException) {
          return '';
        }
        throw error;
      } finally {
        clearTimeout(timeoutId);
      }
    }
  
}