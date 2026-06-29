FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential procps gdb strace man-db manpages-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /stash

CMD ["/bin/bash"]