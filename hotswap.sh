#!/bin/bash

scriptPath=$(dirname "${BASH_SOURCE[0]}")
libPath="$scriptPath/hotswap.so"

HOTSWAP_EXECUTABLE="$1" LD_PRELOAD="$libPath" exec "$@"
