FROM node

WORKDIR /app/dist

# Add sources
ADD package.json   /app/dist/package.json
ADD amnesiac.js    /app/dist/amnesiac.js
ADD test.js        /app/dist/test.js
ADD LICENSE.AGPLv3 /app/dist/LICENSE.AGPLv3

# Install dependencies
RUN npm install
