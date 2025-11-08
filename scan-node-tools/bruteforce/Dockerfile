FROM python:3.11-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl netcat-openbsd tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY bf_runner.py /app/bf_runner.py

# Copy wordlists to workdir for easy access
COPY wordlists/ /app/

VOLUME ["/wordlists"]

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/bf_runner.py"]

RUN useradd -m -u 10001 scanner && chown -R scanner /app
USER scanner