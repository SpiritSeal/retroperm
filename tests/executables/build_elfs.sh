#!/bin/bash

CURRENT_DIR=$(pwd)
cd "$(dirname "$0")" || return

for file in ./src/*.c; do
  gcc "$file" -o "$(basename "${file%.c}")"
done

cd "$CURRENT_DIR" || return
