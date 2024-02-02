#!/bin/bash

# Default values
NAME_PREFIX=""
MAX_SERVERS=0
ROUND=0

# Process named parameters
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --name-prefix) NAME_PREFIX="$2"; shift ;;
        --max-servers) MAX_SERVERS="$2"; shift ;;
        --round) ROUND="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Check if the required parameters are provided
if [ -z "$NAME_PREFIX" ] || [ "$MAX_SERVERS" -eq 0 ] || [ "$ROUND" -eq 0 ]; then
    echo "Usage: $0 --name-prefix [NAME_PREFIX] --max-servers [MAX_SERVERS] --round [ROUND]"
    echo "Example: $0 --name-prefix 'test' --max-servers 5 --round 3"
    exit 1
fi

# Create the output file name with the current date and time
output_file="${NAME_PREFIX}_$(date +'%Y%m%d_%H%M').csv"

# Concatenate the files
for ((i=1; i<=MAX_SERVERS; i++)); do
    file="${NAME_PREFIX}_${i}_${ROUND}.csv"
    if [ -f "$file" ]; then
        # Skip the header from subsequent files
        if [ "$i" -eq 1 ]; then
            cat "$file" > "$output_file"
        else
            tail -n +2 "$file" >> "$output_file"
        fi
    else
        echo "Warning: File not found: $file"
    fi
done

echo "Concatenated file created: $output_file"
