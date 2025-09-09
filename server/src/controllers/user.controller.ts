import { Request, Response, NextFunction } from "express";
import db from "../db";
import bcrypt from "bcrypt";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import CryptoJS from "crypto-js";
import xss from "xss";
import { encryptionKey, encryptionIv } from "../config/cryptoConfig";

// AES Helpers
const algorithm = "aes-256-cbc";

export function encrypt(text: string) {
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, encryptionIv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

export function decrypt(encryptedText: string) {
  const decipher = crypto.createDecipheriv(algorithm, encryptionKey, encryptionIv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Registro seguro
export async function registerSecure(req: Request, res: Response) {
  try {
    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");
    const { encryptedKey, encryptedData } = req.body;

    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      bufferEncryptedKey
    ).toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
    const { username, password } = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    const encryptedUsername = encrypt(xss(username));
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      "INSERT INTO users(username, password) VALUES($1, $2)",
      [encryptedUsername, hashedPassword]
    );

    res.status(201).json({ message: "Usuário registrado com sucesso!" });
  } catch (err: any) {
    console.error(err);
    res.status(400).json({ error: "Falha ao registrar usuário" });
  }
}

// Login seguro
export async function loginSecure(req: Request, res: Response): Promise<void> {
  try {
    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");
    const { encryptedKey, encryptedData } = req.body;

    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      bufferEncryptedKey
    ).toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
    const { username, password } = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    const encryptedUsername = encrypt(xss(username));
    const result = await db.query("SELECT * FROM users WHERE username=$1", [encryptedUsername]);
    
    if (result.rowCount === 0) {
      res.status(401).json({ error: "Credenciais inválidas" });
      return; // ✅ apenas para interromper execução
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      res.status(401).json({ error: "Credenciais inválidas" });
      return; // ✅ interrompe execução
    }

    res.cookie("userId", user.id, { httpOnly: true, maxAge: 60*60*1000, sameSite: "strict", secure: false });
    res.json({ message: "Login realizado com sucesso!" });

  } catch (err: any) {
    console.error(err);
    res.status(400).json({ error: "Falha na autenticação" });
  }
}


// Perfil criptografado
export async function getEncryptedProfile(req: Request, res: Response): Promise<void> {
  try {
    const userId = req.cookies.userId;
    const { encryptedKey } = req.body;

    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");
    const bufferEncryptedKey = Buffer.from(encryptedKey, "base64");
    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      bufferEncryptedKey
    ).toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);

    const result = await db.query("SELECT username FROM users WHERE id=$1", [userId]);
    if (result.rowCount === 0) {
      res.status(404).json({ error: "Usuário não encontrado" });
      return; // ✅ apenas para interromper a função
    }

    const user = result.rows[0];
    const decryptedUsername = decrypt(user.username);

    const payload = JSON.stringify({ username: decryptedUsername });
    const encryptedData = CryptoJS.AES.encrypt(payload, aesKey, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 }).toString();

    res.json({ encryptedData }); // ✅ não usar "return"
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
}
