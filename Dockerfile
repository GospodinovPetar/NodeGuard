FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# nmap has a debian package; gobuster doesn't, so we pull its prebuilt
# release binary directly (arch-aware for amd64/arm64 dev machines).
ARG GOBUSTER_VERSION=3.8.2
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap curl ca-certificates \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) GB_ARCH=x86_64 ;; \
         arm64) GB_ARCH=arm64 ;; \
         *) echo "unsupported arch: $ARCH" >&2 && exit 1 ;; \
       esac \
    && curl -sSL -o /tmp/gobuster.tar.gz \
        "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_${GB_ARCH}.tar.gz" \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY NodeGuard/ .

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
