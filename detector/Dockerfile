FROM python:3.12-slim

LABEL maintainer="HNG DevSecOps"
LABEL description="HNG Anomaly Detection Engine"

# Install iptables and other system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector source files
COPY . .

# Create log directory
RUN mkdir -p /var/log/detector

EXPOSE 8080

# Run as root (needed for iptables)
CMD ["python", "-u", "main.py"]
