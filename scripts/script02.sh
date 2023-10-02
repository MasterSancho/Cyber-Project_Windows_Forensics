#!/bin/bash

# 1. Check User Privileges

# Exit the script if it is not executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "[+] You need to run this script as root."
    echo "    Change to root and run again"
    exit 1
fi

# Continue with the rest of the script.
echo "[+] Running as root. Continuing with the script..."

# 2. Specify and Verify Filename

# Ask the user for the filename or filepath.
read -p "[!] Enter the location of the file for analyzing: " file

# Check if the file exists.
while [[ ! -e $file ]]; do
    echo "[!] File does not exist. Please enter a valid file location."
    read -p "    Enter the location of the file for analyzing: " file
done

echo "[+] File exists. Continuing with the analysis..."
