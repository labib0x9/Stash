FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    build-essential procps gdb strace man-db manpages-dev
RUN apt-get install tree
RUN apt install -y libcap2-bin
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /stash

CMD ["/bin/bash"]