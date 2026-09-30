FROM node:22-alpine

WORKDIR /app

# Install openssl for cryptographic operations, verification and CRL generation
RUN apk add --no-cache openssl bash

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 9000

CMD ["node", "server.js"]
