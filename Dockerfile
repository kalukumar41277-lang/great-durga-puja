FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GREAT_DURGA_HOST=0.0.0.0

WORKDIR /app

RUN useradd --system --uid 10001 --create-home app \
    && mkdir -p /var/data \
    && chown app:app /var/data

COPY --chown=app:app server.py index.html admin.html "WhatsApp Image 2026-10-10 at 21.24.06 (2).jpeg" ./

USER app

EXPOSE 8000

CMD ["python", "server.py"]
