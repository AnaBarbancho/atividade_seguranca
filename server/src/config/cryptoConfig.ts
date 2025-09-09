import crypto from "crypto";

// AES-256-CBC
export const encryptionKey = crypto.randomBytes(32); // 256 bits
export const encryptionIv = crypto.randomBytes(16);  // 128 bits
