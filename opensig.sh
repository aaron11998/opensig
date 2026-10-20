#!/usr/bin/env bash
D=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
PYTHONPATH="$D${PYTHONPATH:+:$PYTHONPATH}" exec "$D/.venv/bin/python" -m opensig.cli "$@"
