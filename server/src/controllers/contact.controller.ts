import { Request, Response } from "express";
import db from "../db";
import xss from "xss";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import CryptoJS from "crypto-js";
import { encryptionKey, encryptionIv } from "../config/cryptoConfig";

const algorithm = "aes-256-cbc";

// 🔐 Helpers AES
function encrypt(text: string) {
  const cipher = crypto.createCipheriv(algorithm, encryptionKey, encryptionIv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decrypt(encryptedText: string) {
  const decipher = crypto.createDecipheriv(algorithm, encryptionKey, encryptionIv);
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ✅ Criar contato
export async function createContact(req: Request, res: Response) {
  try {
    const userId = req.cookies.userId;
    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");
    const { encryptedKey, encryptedData } = req.body;

    // 🔓 Descriptografa chave AES enviada pelo front
    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(encryptedKey, "base64")
    ).toString("utf-8");

    // 🔐 Usa AES para descriptografar o payload
    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });

    const { name, phone } = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    // 🧼 Sanitiza e criptografa
    const encryptedName = encrypt(xss(name));
    const encryptedPhone = encrypt(xss(phone));

    await db.query(
      "INSERT INTO contacts(user_id, name, phone) VALUES($1, $2, $3)",
      [userId, encryptedName, encryptedPhone]
    );

    res.status(201).json({ message: "Contato adicionado com sucesso!" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Falha ao criar contato" });
  }
}

// ✅ Listar contatos
export async function listContacts(req: Request, res: Response) {
  try {
    const userId = req.cookies.userId;
    const { encryptedKey } = req.body;
    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");

    // Descriptografa chave AES
    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(encryptedKey, "base64")
    ).toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);

    // Busca contatos no banco
    const result = await db.query("SELECT id, name, phone FROM contacts WHERE user_id=$1", [userId]);
    const contacts = result.rows.map((row) => ({
      id: row.id,
      name: decrypt(row.name),
      phone: decrypt(row.phone),
    }));

    // Recriptografa para envio
    const payload = JSON.stringify(contacts);
    const encryptedData = CryptoJS.AES.encrypt(payload, aesKey, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    }).toString();

    res.json({ encryptedData });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao listar contatos" });
  }
}

// ✅ Atualizar contato
export async function updateContact(req: Request, res: Response) {
  try {
    const userId = req.cookies.userId;
    const contactId = req.params.id;
    const privateKey = fs.readFileSync(path.join(__dirname, "../../keys/private.pem"), "utf-8");
    const { encryptedKey, encryptedData } = req.body;

    const decryptedKeyBase64 = crypto.privateDecrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
      Buffer.from(encryptedKey, "base64")
    ).toString("utf-8");

    const aesKey = CryptoJS.enc.Base64.parse(decryptedKeyBase64);
    const bytes = CryptoJS.AES.decrypt(encryptedData, aesKey, {
      mode: CryptoJS.mode.ECB,
      padding: CryptoJS.pad.Pkcs7,
    });

    const { name, phone } = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));

    const encryptedName = encrypt(xss(name));
    const encryptedPhone = encrypt(xss(phone));

    await db.query(
      "UPDATE contacts SET name=$1, phone=$2 WHERE id=$3 AND user_id=$4",
      [encryptedName, encryptedPhone, contactId, userId]
    );

    res.json({ message: "Contato atualizado com sucesso!" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Falha ao atualizar contato" });
  }
}

// ✅ Excluir contato
export async function deleteContact(req: Request, res: Response) {
  try {
    const userId = req.cookies.userId;
    const contactId = req.params.id;
    await db.query("DELETE FROM contacts WHERE id=$1 AND user_id=$2", [contactId, userId]);
    res.json({ message: "Contato excluído com sucesso!" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Falha ao excluir contato" });
  }
}
