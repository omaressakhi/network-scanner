# Base image Python slim
FROM python:3.12-slim

# Working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping net-tools tcpdump iproute2 nmap wget \
    && rm -rf /var/lib/apt/lists/*

# Copy scanner code (ieee-oui.txt optional)
COPY scanner.py /app/
# COPY ieee-oui.txt /app/   # optional, remove if not needed

# Install Python dependencies
RUN pip install --no-cache-dir scapy argparse colorama tabulate

# Set entrypoint
ENTRYPOINT ["python", "scanner.py"]

