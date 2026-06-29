#!/bin/bash

CMD=${1:-run}
NAME=${2:-crui}

if [ "$CMD" = "run" ]; then
    docker run -it --rm \
        --name "$NAME" \
        --platform=linux/amd64 \
        --cap-add=SYS_PTRACE \
        --security-opt seccomp=unconfined \
        -v "$(pwd):/stash" \
        crui-dev

elif [ "$CMD" = "exec" ]; then
    docker exec -it "$NAME" bash

else
    echo "usage: $0 [run|exec] [name]"
fi