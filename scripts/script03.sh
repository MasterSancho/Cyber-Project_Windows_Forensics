#!/bin/bash


# Store the directory from where the script is being run
current_directory=$(pwd)

# Construct the path to the Volatility directory
volatility_path="$current_directory/volatility"


# 1.1 Check User Privileges

# Exit the script if it is not executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "[+] You need to run this script as root."
    echo "    Change to root and run again"
    exit 1
fi

# Continue with the rest of the script.
echo "[+] Running as root. Continuing with the analysis..."

# 1.2 Specify and Verify Filename

# Ask the user for the filename or filepath.
read -p "[!] Enter the location of the file for analyzing: " file

# Check if the file exists.
while [[ ! -e $file ]]; do
    echo "[!] File does not exist. Please enter a valid file location."
    read -p "    Enter the location of the file for analyzing: " file
done

echo "[+] File exists. Continuing with the checking tools..."

# 1.3 Function to check and install missing tools
check_and_install() {
    for tool in bulk_extractor binwalk foremost strings; do
        if ! command -v $tool &>/dev/null; then
            echo "[!] $tool is not installed. Installing now..."
            apt install -y $tool
        else
            echo "[+] $tool is installed."
        fi
    done
}

# Function to check the existence of Volatility directory and vol.py
check_volatility() {
    # Check if the Volatility directory exists
    if [[ -d "$volatility_path" ]]; then
        # Now check for vol.py inside the Volatility directory
        if [[ -f "$volatility_path/vol.py" ]]; then
            echo "[+] Volatility is installed."
        else
            echo "[!] vol.py not found inside the Volatility directory."
            install_volatility
        fi
    else
        echo "[!] Volatility not found. Installing now..."
        install_volatility
    fi
}

# Function to install Volatility
install_volatility() {
    git clone https://github.com/volatilityfoundation/volatility.git &>/dev/null

    echo "[+] Installation completed."
    
    # Re-check for Volatility after installation
    check_volatility
}

# Call the function to check and install tools if missing
check_and_install
check_volatility