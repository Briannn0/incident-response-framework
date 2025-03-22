#!/bin/bash
# Common functions for IRF

# Simple logging function
irf_log() {
    local level="$1"
    shift
    echo "[$level] [irf] $*" >&2
}
