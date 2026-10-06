FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000

WORKDIR /app

# Dépendances d'abord (cache de build)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code applicatif (server.py + coxyz_reader.py)
COPY app/ ./

EXPOSE 8000

# L'utilisateur d'exécution (non-root + groupes svc_*) est fixé via compose.
CMD ["python", "server.py"]
