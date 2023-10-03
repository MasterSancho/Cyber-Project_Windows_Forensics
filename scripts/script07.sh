#!/bin/bash

# Global variables
# Store the directory from where the script is being run
current_directory=$(pwd)
# Construct the path to the Volatility directory
volatility_path="$current_directory/volatility3"
# Variable for output directory
output_directory="$current_directory/output"
# Declare memory_file as an empty string
memory_file=""

# 1.1 Check User Privileges
# Exit the script if it is not executed with superuser privileges.
if [[ "${UID}" -ne 0 ]]; then
    echo "[!] You need to run this script as root."
    echo "    Change to root and run again"
    exit 1
fi

# Continue with the rest of the script.
echo " -> Running as root. Continuing with the analysis..."

# 1.2 Specify and Verify Filename
# Ask the user for the filename or filepath.
read -p "[!] Enter the location of the file for analyzing: " file

# After getting the input, convert it to an absolute path
file=$(realpath "$file")

# Check if the file exists.
while [[ ! -e $file ]]; do
    echo "[!] File does not exist. Please enter a valid file location."
    read -p " -> Enter the location of the file for analyzing: " file
    file=$(realpath "$file")  # Convert to absolute path again
done

# Assign the file value to memory_file
memory_file=$file

echo " -> File exists. Continuing with the checking tools..."

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
    git clone https://github.com/volatilityfoundation/volatility3.git &>/dev/null

    echo "[+] Installation completed."
    
    # Re-check for Volatility after installation
    check_volatility
}

# 1.4 & 1.5 
## Function to unzip all zip files in a output directory and its subdirectories
unzip_files() {
    echo " -> Searching for zip files..."
    
    local directory="$1" # The directory to search in

    # Find all zip files in the specified directory and its subdirectories
    local zip_files=$(find "$directory" -type f -name '*.zip')

    # If zip files are found, unzip them
    if [[ ! -z "$zip_files" ]]; then
        echo "[+] Found zip files. Unzipping..."
        for zip_file in $zip_files; do
            # Unzip the zip_file to the directory containing the zip file
            unzip -o "$zip_file" -d "$(dirname "$zip_file")" &>/dev/null
        done
    else
        echo "[!] No zip files found."
    fi
}

# Use different carvers to automatically extract data
carve_data() {
    echo " -> Extracting data from file..."
    
    # Check if output directory exists, if not, create it
    mkdir -p $output_directory
    
    echo "[+] Using Bulk Extractor to extract data..."
    bulk_extractor -o $output_directory/bulk_extractor $file &>/dev/null
    
    echo "[+] Using Binwalk to extract data..."
    mkdir -p $output_directory/binwalk
    binwalk -e --run-as=root -C $output_directory/binwalk $file &>/dev/null
    
    echo "[+] Using Foremost to extract data..."
    foremost -i $file -o $output_directory/foremost &>/dev/null
    
    echo "[+] Using Strings to extract data..."
    strings $file > $output_directory/strings_output.txt

    # Call the unzip_files function to unzip any zip files that were extracted
    unzip_files "$output_directory"
}

# 1.6 Function to find and display pcap files
find_pcap_files() {
    local directory="$1" # The directory to search in

    # Find pcap files in the specified directory and its subdirectories
    local pcap_files=$(find "$directory" -type f -name '*.pcap')

    # If pcap files are found, display their location and size
    if [[ ! -z "$pcap_files" ]]; then
        echo "[+] Found pcap files:"
        for file in $pcap_files; do
            local size=$(du -h "$file" | cut -f1) # Get the size of the file
            echo " -> Location: $file"
            echo " -> Size: $size"
        done
    else
        echo "[!] No pcap files found."
    fi
}

# 1.7 Function to check for human-readable strings such as exe files, passwords, usernames, etc.
find_human_readable() {
    echo " -> Searching for human readable data..."
    
    local directory="$1" # The directory to search in
    
    # Create a directory to store the pattern match results
    local result_directory="$current_directory/forensics_analysis_data"
    mkdir -p "$result_directory"

    # Define patterns to search for
    local patterns=("exe" "passwd" "username")

    # Loop through each pattern and search in the directory
    for pattern in "${patterns[@]}"; do
        echo "[+] Searching for '$pattern'..."
        
        # Use grep to search for the pattern in the directory
        local matches=$(grep -r -i -n -o -P "$pattern" "$directory" 2>/dev/null | sort | uniq)
        
        # If matches are found, save them to a file and notify the user
        if [[ ! -z "$matches" ]]; then
            local result_file="$result_directory/${pattern}s.txt"
            echo "$matches" > "$result_file"
            echo "[+] Matches found for '$pattern'"
            echo " -> saved in ${result_file}"
        else
            echo "[!] No matches found for '$pattern'."
        fi
    done
}

volatility_analysis() {
    echo " -> Running volatility analysis on the memory dump: $memory_dump"

    local result_directory="$current_directory/forensics_analysis_data"
    local result_file="$result_directory/image_info"
    local processes_file="$result_directory/processes_info"
    local netscan_file="$result_directory/network_connections"
    local registry_file="$result_directory/registry_info"
    
    # Make sure the result directory exists
    mkdir -p "$result_directory"

    # Run the volatility analysis and redirect its output to image_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.info.Info > "$result_file" 2>&1

    if [[ $? -eq 0 ]]; then
        echo "[+] Volatility analysis completed."
        echo " -> Results saved in ${result_file}"
    else
        echo "[!] There was an error running the volatility analysis."
        return
    fi

    # List the running processes and save to processes_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.pslist.PsList > "$processes_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Running processes listed successfully."
        echo " -> Processes saved in ${processes_file}"
    else
        echo "[!] There was an error listing the running processes."
    fi

     # Now, display the network connections and save to network_connections
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.netscan.NetScan > "$netscan_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Network connections listed successfully."
        echo " -> Network connections saved in ${netscan_file}"
    else
        echo "[!] There was an error listing the network connections."
    fi

    # Extract registry information and save to registry_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.registry.hivelist.HiveList > "$registry_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Registry information extracted successfully."
        echo " -> Registry data saved in ${registry_file}"
    else
        echo "[!] There was an error extracting the registry information."
    fi
}


# Call the functions
check_and_install
check_volatility
carve_data
find_pcap_files "$output_directory"
find_human_readable "$output_directory"
volatility_analysis





