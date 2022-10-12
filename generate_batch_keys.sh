#!/usr/bin/env bash

GPU_INDEX=$1
KEY_COUNT=$2
OUTPUT_FOLDER=$3

if [ -z "$OUTPUT_FOLDER" ]; then
    echo "Usage: $0 GPU_INDEX KEY_COUNT OUTPUT_FOLDER"
    exit 1
fi

mkdir -p $OUTPUT_FOLDER > /dev/null 2>&1

for i in `seq 1 $KEY_COUNT`; do 
    CUDA_DEVICE_ORDER="PCI_BUS_ID" CUDA_VISIBLE_DEVICES="$GPU_INDEX" \
        ./gpg-fingerprint-filter-gpu \
        -a ed25519 \
        -b 1420000000 \
        "x{11}|xxxxxxy{6}|wwwwxxxxyyyyzzzz|xxxxy{8}|xxxxxxxxyyyy|(wxyz){4}|1145141919810" \
        $OUTPUT_FOLDER/$(date +%s)$RANDOM
    sleep 0.5 
done
