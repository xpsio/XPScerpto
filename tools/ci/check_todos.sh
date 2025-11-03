#!/usr/bin/env bash
set -euo pipefail
hits=$(grep -RInE '\b(TODO|FIXME|WIP|TBD)\b' "$@" || true)
if [ -n "$hits" ]; then echo "$hits"; exit 1; fi
