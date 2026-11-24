# Build from the repository root:  docker build -f cloud/Dockerfile -t sra-riskgate-cloud .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SRA_CLOUD_DB=/data/sra-cloud.db

WORKDIR /src
COPY pyproject.toml README.md LICENSE CHANGELOG.md MANIFEST.in ./
COPY sra_riskgate ./sra_riskgate
COPY cloud ./cloud
RUN pip install . "./cloud[x402]" && rm -rf /src

RUN useradd --create-home --uid 10001 sra && mkdir -p /data && chown sra /data
USER sra
WORKDIR /home/sra
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"
CMD ["sra-cloud", "serve", "--host", "0.0.0.0", "--port", "8080"]
