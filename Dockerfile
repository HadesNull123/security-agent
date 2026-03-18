# =============================================================================
# Security Agent - Multi-stage Docker Build
# Includes all security tools pre-installed
# =============================================================================

FROM python:3.11-slim AS base

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    unzip \
    build-essential \
    libssl-dev \
    libffi-dev \
    nmap \
    nikto \
    dirb \
    sqlmap \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Install Go-based tools (ProjectDiscovery suite + extras)
# ---------------------------------------------------------------------------
FROM golang:1.22-bookworm AS go-builder

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/ffuf/ffuf/v2@latest \
    && go install -v github.com/OJ/gobuster/v3@latest \
    && go install -v github.com/owasp-amass/amass/v4/...@master \
    && go install -v github.com/hahwul/dalfox/v2@latest \
    && go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# ---------------------------------------------------------------------------
# Final image
# ---------------------------------------------------------------------------
FROM base AS final

# Copy Go binaries
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/naabu /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/
COPY --from=go-builder /go/bin/gobuster /usr/local/bin/
COPY --from=go-builder /go/bin/amass /usr/local/bin/
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/
COPY --from=go-builder /go/bin/crlfuzz /usr/local/bin/

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install Python-based security tools
RUN pip install --no-cache-dir theharvester wafw00f commix corscanner PyPDF2

# Install SearchSploit
RUN git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && chmod +x /opt/exploitdb/searchsploit

# Download Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Download common wordlists
RUN mkdir -p /usr/share/wordlists && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /usr/share/wordlists/common.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
    -o /usr/share/wordlists/directory-list-small.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -o /usr/share/wordlists/directory-list-medium.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt \
    -o /usr/share/wordlists/raft-large-files.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt \
    -o /usr/share/wordlists/quickhits.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    -o /usr/share/wordlists/subdomains-top5000.txt

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

# Copy application code
COPY . .

# Create directories
RUN mkdir -p /app/data /app/reports

# Set entrypoint
ENTRYPOINT ["python", "-m", "src.cli"]
CMD ["--help"]
