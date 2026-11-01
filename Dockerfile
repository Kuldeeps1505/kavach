FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY src/ /app/src/
COPY web/ /app/web/

RUN mkdir -p /var/lib/kavach /data/watch \
    && chown -R 10001:10001 /var/lib/kavach /data/watch

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

ENTRYPOINT ["python", "-m", "kavach"]
CMD ["--watch-dir", "/data/watch", "--database", "/var/lib/kavach/kavach.sqlite3", "--api-host", "0.0.0.0", "--api-port", "8000"]
