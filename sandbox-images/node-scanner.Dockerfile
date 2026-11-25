FROM node:20-slim
RUN npm install -g eslint eslint-plugin-security npm-audit-html
RUN useradd -m scanner
USER scanner
WORKDIR /workspace
