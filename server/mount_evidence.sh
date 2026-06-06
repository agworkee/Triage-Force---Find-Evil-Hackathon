#!/usr/bin/env bash
# ==============================================================================
# SIFT Workstation Mount Script for TriageForce
# Securely mounts a raw/E01 image read-only under /cases to prevent evidence spoliation.
# ==============================================================================

set -euo pipefail

CASE_ID="case_001"
MOUNT_ROOT="/cases/${CASE_ID}"
IMAGE_DIR="${MOUNT_ROOT}/image"
EVIDENCE_DIR="${MOUNT_ROOT}/evidence"
MOUNT_POINT="${MOUNT_ROOT}/mount"

# Ensure the /cases folders exist
sudo mkdir -p "$IMAGE_DIR" "$EVIDENCE_DIR" "$MOUNT_POINT"

echo "=== TriageForce Mount Utility ==="
echo "Evidence and cases environment initialized under /cases/${CASE_ID}"

# In SIFT, EWF/E01 files are mounted using ewfmount or xmount.
# Since SIFT has ewfmount preinstalled:
# usage: ewfmount <image_file> <mount_dir>

E01_FILE="${IMAGE_DIR}/dmz-ftp-cdrive.E01"

if [ ! -f "$E01_FILE" ]; then
    echo "ERROR: dmz-ftp-cdrive.E01 not found at $E01_FILE."
    echo "Please SCP/transfer the file to sansforensics@192.168.255.128:$E01_FILE first!"
    exit 1
fi

echo "Staging E01 image mounting..."
# 1. Mount E01 as a raw image using ewfmount
sudo ewfmount "$E01_FILE" "$EVIDENCE_DIR"

# At this stage, a raw disk image file 'ewf1' will appear under $EVIDENCE_DIR
RAW_IMAGE="${EVIDENCE_DIR}/ewf1"

if [ -f "$RAW_IMAGE" ]; then
    echo "E01 successfully mounted as RAW image file: $RAW_IMAGE"
    
    # 2. Bind-mount the raw file as a read-only partition for safe triaging
    echo "Performing secure read-only bind-mount of the evidence directory..."
    sudo mount --bind "$EVIDENCE_DIR" "$EVIDENCE_DIR"
    sudo mount -o remount,ro,bind "$EVIDENCE_DIR"
    
    echo "Success! Evidence directory $EVIDENCE_DIR is now mounted READ-ONLY."
    echo "No modifications can be made to the original files, assuring complete integrity."
else
    echo "ERROR: Failed to mount E01 image as raw file."
    exit 1
fi
