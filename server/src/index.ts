import path from "path";
import fs from "fs";
import https from "https";
import express from "express";
import cookieParser from "cookie-parser";
import userRoutes from "./routes/user.routes";

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Rotas da API
app.use("/api", userRoutes);

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
