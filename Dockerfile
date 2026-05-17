FROM python:3.11-slim

LABEL maintainer="harunidev"
LABEL description="Solidity/EVM smart contract security auditor"

WORKDIR /app

# Install deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .
RUN pip install --no-cache-dir -e .

# Non-root user
RUN useradd -m audituser && chown -R audituser:audituser /app
USER audituser

EXPOSE 5000

# Default: web server; override for CLI usage
CMD ["python", "main.py", "web"]
