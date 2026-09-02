FROM python:3.11-slim

# Install system dependencies (ClamAV & build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-freshclam \
    libyara-dev \
    && pip install --no-cache-dir \
    yara-python \
    oletools \
    pefile \
    pypdf \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /sandbox

# Copy YARA rules, analyzer & daemon server
COPY rules /sandbox/rules
COPY analyze.py /sandbox/analyze.py
COPY server.py /sandbox/server.py

RUN chmod +x /sandbox/analyze.py /sandbox/server.py

EXPOSE 5005

CMD ["python", "/sandbox/server.py"]
