FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    tcpdump \
    procps \
    curl \
    gcc \
    libc6-dev \
    wine64 \
    inetsim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY monitor.py hook_agent.py vm_spoof.c ./

RUN gcc -shared -fPIC -O2 -o /app/vm_spoof.so /app/vm_spoof.c

ENTRYPOINT ["python", "/app/monitor.py"]
