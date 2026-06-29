docker run -it --rm \
    --platform=linux/amd64 \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v $(pwd):/stash crui-dev