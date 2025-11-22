FROM python:3.11-slim

WORKDIR /app


RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .


RUN pip install --no-cache-dir -r requirements.txt 


COPY faq_backend.py .


RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser


EXPOSE 3001


HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1


CMD ["gunicorn", "faq_backend:app", \
     "--bind", "0.0.0.0:3001", \
     "--workers", "2", \
     "--worker-class", "gevent", \
     "--worker-connections", "100", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]