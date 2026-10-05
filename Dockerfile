# syntax=docker/dockerfile:1
# Pathfinder MCP — self-contained recon server.
# CLI tools are preinstalled; anything missing still degrades to MISSING_TOOL.
FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}"

# nmap + ffuf are in apt; subfinder/httpx/nuclei are Go binaries fetched below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl unzip nmap ffuf dnsutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Prebuilt projectdiscovery binaries — no Go toolchain needed.
ARG PD_VERSION=v1.1.0
RUN for spec in \
        "subfinder https://github.com/projectdiscovery/subfinder/releases/download/${PD_VERSION}/subfinder_${PD_VERSION}_linux_amd64.zip" \
        "nuclei   https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip"; do \
        set -- ${spec}; \
        curl -fsSL "$2" -o /tmp/$1.zip && \
        unzip -q -o /tmp/$1.zip -d /usr/local/bin "$1" && \
        chmod +x /usr/local/bin/$1 && \
        rm -f /tmp/$1.zip; \
    done

# Python app — pinned, no dev deps in the final image.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Nuclei templates are ~200MB; fetch only if the consumer wants them.
# RUN nuclei -update-templates

WORKDIR /workspace
VOLUME ["/workspace"]

# MCP runs over stdio. The client (Claude Code, Hermes, ...) spawns the container
# and speaks JSON-RPC on its stdin/stdout, so keep it foreground + unbuffered.
ENTRYPOINT ["pathfinder"]
