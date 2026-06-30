#!/bin/bash

PID=$1
gcc dump.c -o dump && ./dump "$PID"