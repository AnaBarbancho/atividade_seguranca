import express from "express";
import path from "path";
import fs from "fs";

const router = express.Router();

// Endpoint para fornecer a chave pública
router.get("/public-key", (_, res) => {
  // Leitura da chave pública RSA
  const publicKey = fs.readFileSync(
    //path.join(__dirname, "../keys/public.pem"),
    path.join(__dirname, "..", "..", "keys", "public.pem"),
    "utf-8"
  );

  res.type("text/plain").send(publicKey);
});

export default router;
