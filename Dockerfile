FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=0 \
    HOME=/home/scanner

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin scanner
WORKDIR /app
COPY --chown=scanner:scanner . .
RUN python -m pip install --no-cache-dir --no-compile . \
    && rm -rf /root/.cache

USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["nigerian-scan"]
