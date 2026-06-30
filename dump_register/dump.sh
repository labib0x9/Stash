#!/bin/bash

PID=$1
gcc dump_parser.c -o dump && ./dump "$PID"