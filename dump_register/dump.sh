#!/bin/bash

PID=$1
gcc dump_full.c -o dump && ./dump "$PID"