FROM python:3.12-slim

# Install iptables and network tools for transparent proxy testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install proxy-tuner
WORKDIR /app
COPY . .
RUN pip install -e ".[dev]"

# Default: run tests
CMD ["python", "-m", "pytest", "tests/", "-v"]
