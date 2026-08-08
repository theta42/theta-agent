FROM node:20-alpine
RUN apk add --no-cache bash
WORKDIR /demo
COPY get-secret.sh get-secret.js ./
RUN chmod +x get-secret.sh
CMD ["sh", "-c", "sh /demo/get-secret.sh && node /demo/get-secret.js"]
