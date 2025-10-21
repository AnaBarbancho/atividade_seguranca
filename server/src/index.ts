import path from "path";
import fs from "fs";
import https from "https";
import express from "express";
import cookieParser from "cookie-parser";
import userRoutes from "./routes/user.routes";
import cryptoRoutes from "./routes/crypto"; // rota que retorna public.pem
import contactRoutes from "./routes/contact.routes";

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Rotas da API
app.use("/api/crypto", cryptoRoutes); // chave pública RSA
app.use("/api/user", userRoutes);     // registro/login/profile
app.use("/api/contacts", contactRoutes);

// Servir arquivos estáticos da pasta "public"
const publicPath = path.join(__dirname, "../public");
app.use(express.static(publicPath));

// Redirecionar "/" para seu HTML principal
app.get("/", (req, res) => {
  res.sendFile(path.join(publicPath, "secure-login.html"));
});

// HTTPS
const server = https.createServer(
  {
    key: fs.readFileSync(path.join(__dirname, "../certs/key.pem")),
    cert: fs.readFileSync(path.join(__dirname, "../certs/cert.pem")),
  },
  app
);

server.listen(3000, () => {
  console.log("Servidor rodando em https://localhost:3000");
});
