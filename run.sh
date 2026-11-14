#!/bin/sh
set -eu

cd "$(dirname "$0")"
if [ "$#" -eq 0 ]; then
    set -- gui
fi
exec cargo run --release -- "$@"
