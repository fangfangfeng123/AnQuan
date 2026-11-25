FROM openjdk:21-slim
# 预留：spotbugs / dependency-check
RUN useradd -m scanner
USER scanner
WORKDIR /workspace
