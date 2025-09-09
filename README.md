## Segurança no Desenvolvimento de Aplicações

Este repositório contém o código utilizado na aula sobre **falhas criptográficas (Cryptographic Failures)**, com foco em boas práticas para proteger dados sensíveis durante o processo de autenticação e transmissão de informações entre cliente e servidor.


### Objetivos

O projeto tem como finalidade demonstrar, na prática, como implementar mecanismos de segurança para proteger dados de usuários, tanto no armazenamento quanto na comunicação entre cliente e servidor. Os principais temas abordados são:

1. Armazenamento seguro de senhas com `bcrypt`;
2. Criptografia de dados sensíveis com **criptografia híbrida (AES + RSA-OAEP)**;
3. Criação e verificação de sessões seguras com `cookies` HTTP-only;
4. Utilização de **HTTPS com certificado autoassinado** para ambiente local;
5. Criptografia determinística para campos sensíveis, como email, usando `AES-256-CBC`.


### Como executar o projeto no seu computador

1. Clonando o repositório e instalando as dependências:
```bash
git clone https://github.com/arleysouza/cryptographic-failures.git app
cd app/serer
npm i
```

2. Configurando o BD PostgreSQL
- Crie um BD chamado `bdaula` no PostgreSQL (ou outro nome de sua preferência);
- Atualize o arquivo `server/.env` com os dados de acesso ao banco;

3. Execute os comandos SQL presentes no arquivo `db/comandos.sql` para criar a tabela `users`;

4. Gerar o par de chaves RSA (criptografia assimétrica):
No terminal (Git Bash ou similar), na raiz do projeto:
```bash 
# Criar a pasta
mkdir server/keys
# Criar a chave privada
openssl genrsa -out server/keys/private.pem 2048
# Criar a chave pública
openssl rsa -in server/keys/private.pem -outform PEM -pubout -out server/keys/public.pem
```

5. Gerar certificado HTTPS Local com OpenSSL:
Ainda na raiz do projeto:
```bash 
# Criar a pasta
mkdir server/certs
# Gerar chave privada
openssl genrsa -out server/certs/key.pem 2048
# Gerar certificado autoassinado
openssl req -new -x509 -key server/certs/key.pem -out server/certs/cert.pem -days 365
```
Durante a execução, pressione Enter para usar os valores padrão ou forneça dados conforme desejar.

6. Iniciando o servidor, é necessário estar na raiz do projeto:
```
npm start
npm run dev
```
O servidor estará rodando na porta **3001**.


### Como executar o projeto no Docker

1. Clonando o repositório e instalando as dependências:
```bash
git clone https://github.com/arleysouza/cryptographic-failures.git app
```

2. FFazer o build da imagem e subir os containers:
```bash
docker compose up --build -d
```
O servidor estará rodando na porta **3002**.


### Funcionalidades de Segurança

- Registro seguro (`/api/user/register-secure`) com criptografia híbrida (dados com AES e chave com RSA);
- Login seguro (`/api/user/login-secure`) com descriptografia dos dados no backend e autenticação baseada em senha hash;
- Armazenamento seguro do email com criptografia simétrica (AES-256-CBC com chave fixa);
- Cookie de sessão HTTP-only para autenticação persistente;
- Perfil do usuário (`/secure-profile.html`) com dados transmitidos criptografados do backend para o frontend;
- Middleware de autenticação localizado em `src/middlewares/authentication.ts`.


### Estrutura de Pastas

```bash
app
├── db
│   └── comandos.sql    → Script SQL para criação da tabela users
│
├── server/
│   ├── certs/      → Certificados HTTPS (gerados localmente)
│   ├── keys/       → Par de chaves RSA (privada e pública)
│   │
│   ├── public/
│   │   ├── insecure-register.html    → Página de cadastro sem criptografia
│   │   ├── secure-login.html    → Página de login criptografado
│   │   ├── secure-profile.html  → Página de perfil com decodificação local
│   │   └── secure-register.html → Página de cadastro criptografado
│   │
│   └── src/
│       ├── config/          → Arquivo cryptoConfig.ts com chave e IV fixos
│       ├── middlewares/     → Middleware de autenticação
│       ├── controllers/     → Funções de login, registro, perfil etc.
│       ├── routes/          → Definição das rotas
│       └── index.ts     
│
└── docker-compose.yml
```


### Aviso

Este projeto tem finalidade exclusivamente educacional. Apesar de boas práticas de segurança estarem implementadas, não é recomendado o uso em ambientes de produção sem as devidas adequações e validações adicionais, como:
- Uso de HTTPS com certificado válido;
- Armazenamento seguro de chaves e segredos com `dotenv` ou `Vault`;
- Proteções contra CSRF, XSS e validação robusta de entrada.