FROM golang:1.22-alpine
# 预留：gosec / govulncheck
RUN adduser -D scanner
USER scanner
WORKDIR /workspace
