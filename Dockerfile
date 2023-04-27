FROM node:14

WORKDIR /usr/src/app

COPY package*.json ./

COPY plugin/ ./plugin/

RUN npm ci

COPY . .

EXPOSE 3000

CMD [ "npm", "run", "dev" ]