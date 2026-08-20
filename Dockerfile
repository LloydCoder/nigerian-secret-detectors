FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 scanner
WORKDIR /app
COPY . .
RUN python -m pip install --no-cache-dir .

USER scanner
ENTRYPOINT ["nigerian-scan"]
