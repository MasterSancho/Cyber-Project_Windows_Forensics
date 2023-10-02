#!/bin/bash

# 1. Check User Privileges

# Exit the script if it is not executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "[+] You need to run this script as root."
    echo "    Change to root and run again"
    exit 1
fi

# Continue with the rest of the script.
echo "Running as root. Continuing with the script..."


