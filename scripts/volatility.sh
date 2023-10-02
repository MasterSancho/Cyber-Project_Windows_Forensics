#!/bin/bash

# Store the directory from where the script is being run
current_directory=$(pwd)

# Construct the path to the Volatility directory
volatility_path="$current_directory/volatility"

# Function to check the existence of Volatility directory and vol.py
check_volatility() {
    # Check if the Volatility directory exists
    if [[ -d "$volatility_path" ]]; then
        # Now check for vol.py inside the Volatility directory
        if [[ -f "$volatility_path/vol.py" ]]; then
            echo "Volatility is installed."
        else
            echo "vol.py not found inside the Volatility directory."
            install_volatility
        fi
    else
        echo "Volatility not found. Installing now..."
        install_volatility
    fi
}

# Function to install Volatility
install_volatility() {
    git clone https://github.com/volatilityfoundation/volatility.git &>/dev/null

    echo "Installation completed."
    
    # Re-check for Volatility after installation
    check_volatility
}

# Wrapper function to manage Volatility
manage_volatility() {
    # Call the function
    check_volatility
}

# Call the wrapper function
manage_volatility