FROM python:3.12-slim
RUN pip install --no-cache-dir --index-url https://pypi.tuna.tsinghua.edu.cn/simple semgrep bandit pip-audit safety
RUN pip install --no-cache-dir --index-url https://pypi.tuna.tsinghua.edu.cn/simple flask flask-sqlalchemy
RUN useradd -m scanner
USER scanner
WORKDIR /workspace
