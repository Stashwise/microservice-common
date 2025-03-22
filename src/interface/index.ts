interface DefaultAttributes {
    _id: string;
    createdAt: string;
    updatedAt: string;
}
  
export interface AuthSigning {
    access_token: string;
    refresh_token: string
}

export interface IHash { 
    CRYPTO_SECRET: string; 
    CRYPTO_TIME_STEP: number; 
    CRYPTO_OTP_LENGTH: number; 
    CRYPTO_HASH_ALGO: string; 
    SALT_ROUND: number; 
    STASHWISE_ENCRYPTIONKEY: string; 
    STASHWISE_ENCRYPTIONIV: string; 
}
  
export interface SignedData {
    _id: string;
    email: string;
    time: Date;
    expiresAt: any
}
  
export interface IFileUpload {
    file_name: string;
    file_path: string;
    content_type: string;
}

export interface IMail {
    email: string
    name?: string
    subject: string
    username?: string
    first_name: string
    data?: any
    attachments?: any
}

export interface IUser extends DefaultAttributes {
    first_name: string,
    last_name: string,
    username: string,
    email: string,
    password: string,
    phone: string,
    avatar?: string,
    status?: string,
    gender?: 'Female' | 'Male',
    date_of_birth?: Date,
    is_verified_email: boolean,
    is_created_pin: boolean,
    is_bvn_verified: boolean,
    is_completed_onboarding_kyc: boolean,
    is_deleted: boolean,
    is_push_notification_allowed: boolean,
    referral_code?: string,
    date_joined?: Date,
    last_login?: Date,
    date_deleted?: Date,
    last_failed_attempt?: Date,
    source: string,
    pin: string,
    fcm_token: string,
    bvn: string,
    vault_id: string | IVault,
    banks?: IBank[],
    next_of_kin?: {
      phone?: string,
      address?: string,
      relationship?: string,
      full_name?: string,
    }
}
  
export interface IVault extends DefaultAttributes {
    balance: number,
    account_number: string,
    account_name: string,
    bank: string,
    bank_code: string,
    user_id: string,
    tag: string,
    client_id: string,
    account_id: string,
}
  
 export interface ICoin extends DefaultAttributes {
    balance: number,
    credit: number,
    debit: number,
    account_number: string,
    user_id: string,
}

export interface IBank {
    _id?: string;
    account_number: string
    account_name: string
    bank_name: string
    bank_code: string
    account_id: string
    client_id: string
}

export interface INotification extends DefaultAttributes {
    user_id: string,
    is_read: boolean,
    title: string,
    content: string,
    is_general: boolean
}
  
export interface InitalizedPay {
    authorization_url: string;
    access_code: string;
    reference: string;
}
  
export interface IBVNResponse {
    bvn: string;
    date_of_birth: string;
    first_name: string;
    last_name: string;
    middle_name: string;
    gender: string;
    image: string;
    phone_number1: string;
    phone_number2: string;
    customer: string;
}

export interface JobOptions {
    name: string,
    data: any,
    priority?: number,
    repeat?: any
    delay?: number,
    removeOnComplete?: boolean
}
  
export interface JobEventPayload {
    id: string;
    name: string
}
  
export interface JobFailedEventPayload extends JobEventPayload {
    attemptsMade: number;
    failedReason: string;
    stacktrace: string[]
}