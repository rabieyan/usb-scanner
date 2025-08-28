FROM python:3.12-slim

# System deps for file type detection, clamav, exiftool, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clamav clamav-freshclam \
      file \
      exiftool \
      ca-certificates \
      gcc \
      make \
      libtool \
      pkg-config \
      libssl-dev \
      && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Freshen ClamAV db at build-time (you can also cron-update on the host if preferred)
RUN freshclam || true

WORKDIR /app
COPY scanner.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Non-root for safety
RUN useradd -m scanner
USER scanner

ENTRYPOINT ["/app/entrypoint.sh"]
