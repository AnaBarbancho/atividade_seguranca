# Dockerfile
FROM node:20-alpine

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de dependências primeiro (para otimizar cache)
COPY package*.json ./

# Instala dependências (incluindo devDependencies, necessário para TypeScript)
RUN npm install

# Copia todo o restante do código fonte
COPY . .

# Copia as pastas com chaves e certificados
COPY keys ./keys
COPY certs ./certs


# Compila TypeScript para JavaScript em /dist
RUN npm run build

# Expõe a porta que o servidor HTTPS vai rodar
EXPOSE 3000

# Inicia o servidor a partir do código compilado
CMD ["node", "dist/index.js"]
