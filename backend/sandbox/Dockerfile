FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CAPA_RULES_PATH=/sandbox/capa-rules

# 1. System dependencies: ClamAV, ClamAV Daemon, libmagic, libyara, exiftool, p7zip, git, curl, and build toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    libyara-dev \
    libmagic1 \
    libmagic-dev \
    exiftool \
    p7zip-full \
    curl \
    git \
    gcc \
    build-essential \
    python3-dev \
    && pip install --no-cache-dir \
    yara-python \
    oletools \
    pefile \
    pypdf \
    python-magic \
    flare-capa \
    cryptography \

    # Remove compiler packages to keep image lightweight
    && apt-get purge -y gcc build-essential python3-dev libmagic-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# 2. Download official ClamAV databases (main, daily, bytecode)
RUN freshclam --quiet || true

# 3. Pull official community rulesets (Neo23x0 Signature-Base & Mandiant Capa Rules)
RUN mkdir -p /sandbox/rules/signature_base /sandbox/capa-rules \
    && git clone --depth 1 https://github.com/Neo23x0/signature-base.git /tmp/sigbase \
    && cp /tmp/sigbase/yara/*.yar /sandbox/rules/signature_base/ \
    && rm -rf /tmp/sigbase \
    && git clone --depth 1 https://github.com/mandiant/capa-rules.git /sandbox/capa-rules \
    && rm -rf /sandbox/capa-rules/.git

# 4. Create unprivileged sandbox user
RUN useradd -m -u 1000 sandboxuser

# 5. Configure ClamAV socket directory and file permissions for sandboxuser
RUN mkdir -p /var/run/clamav \
    && chown -R sandboxuser:sandboxuser /var/run/clamav /var/lib/clamav \
    && chmod -R 755 /var/lib/clamav /var/run/clamav

COPY clamd.conf /etc/clamav/clamd.conf
RUN chown sandboxuser:sandboxuser /etc/clamav/clamd.conf && chmod 644 /etc/clamav/clamd.conf

WORKDIR /sandbox

# 6. Copy compiler, analyzer, entrypoint, and server
COPY compile_rules.py /sandbox/compile_rules.py
COPY analyze.py /sandbox/analyze.py
COPY server.py /sandbox/server.py
COPY entrypoint.sh /sandbox/entrypoint.sh

# 7. Pre-compile 734+ official Florian Roth / Neo23x0 community rulesets
RUN python /sandbox/compile_rules.py \
    && chown -R sandboxuser:sandboxuser /sandbox \
    && chmod -R 755 /sandbox /sandbox/entrypoint.sh

# 8. Switch to unprivileged sandbox user
USER sandboxuser

EXPOSE 5005

ENTRYPOINT ["/bin/bash", "/sandbox/entrypoint.sh"]
