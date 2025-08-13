#!/bin/bash
for file in *.tf; do
    echo "=== $file ==="
    cat "$file"
    echo
done
