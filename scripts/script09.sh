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
# Global variable to store start time
start_time=$(date +%s)

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

# Check if the file exists.
while [[ ! -e $file ]]; do
    echo "[!] File does not exist. Please enter a valid file location."
    read -p " -> Enter the location of the file for analyzing: " file
done

# Assign the file value to memory_file
memory_file=$file

echo " "
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
    echo " "
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
    echo " "
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
    echo " "
    echo " -> Searching for pcap files..."

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
    echo " "
    echo " -> Searching for human readable data..."
    
    local directory="$1" # The directory to search in
    
    # Create a directory to store the pattern match results
    local result_directory="$current_directory/forensics_analysis_data"
    mkdir -p "$result_directory"

    # Define patterns to search for
    local patterns=("exe" "passwd" "username")

    # Loop through each pattern and search in the directory
    for pattern in "${patterns[@]}"; do
        echo " -> Searching for '$pattern'..."
        
        # Use grep to search for the pattern in the directory
        local matches=$(grep -r -i -o -P "$pattern" "$directory" 2>/dev/null | sort | uniq)
        
        # If matches are found, save them to a file and notify the user
        if [[ ! -z "$matches" ]]; then
            local result_file="$result_directory/${pattern}s.txt"
            echo "$matches" > "$result_file"
            echo "[+] Matches found for '$pattern' -> saved"
        else
            echo "[!] No matches found for '$pattern'."
        fi
    done
}

volatility_analysis() {
    echo " "
    echo " -> Running volatility analysis on the memory dump: $memory_dump"

    local result_directory="$current_directory/forensics_analysis_data"
    local result_file="$result_directory/volatility_windows_info"
    local processes_file="$result_directory/volatility_processes_info"
    local netscan_file="$result_directory/volatility_network_connections_info"
    local registry_file="$result_directory/volatility_registry_info"
    
    # Make sure the result directory exists
    mkdir -p "$result_directory"

    # Run the volatility analysis and redirect its output to image_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.info.Info > "$result_file" 2>&1

    if [[ $? -eq 0 ]]; then
        echo "[+] Volatility windows info completed -> saved"
    else
        echo "[!] There was an error running the windows Info."
        return
    fi

    # List the running processes and save to processes_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.pslist.PsList > "$processes_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Volatility processes pslist completed  -> saved"
    else
        echo "[!] There was an error running processes PsList."
    fi

     # Now, display the network connections and save to network_connections
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.netscan.NetScan > "$netscan_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Volatility Network connections NetScan completed  -> saved"
    else
        echo "[!] There was an error running network connections NetScan."
    fi

    # Extract registry information and save to registry_info
    python3 "$volatility_path/vol.py" -f "$memory_file" windows.registry.hivelist.HiveList > "$registry_file" 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "[+] Volatility Registry information HiveList completed  -> saved"
    else
        echo "[!] There was an error running registry information HiveList."
    fi
}

# Function to display the results
display_statistics() {
    # Get the current date and time in the specified format
    current_date_time=$(date +"%a %b %d %I:%M:%S %p %Z %Y")
    
    # Extract the filename from the memory_file variable
    file_name=$(basename "$memory_file")

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Convert duration to hours:minutes:seconds
    local hours=$((duration / 3600))
    local minutes=$(((duration / 60) % 60))
    local seconds=$((duration % 60))

    # File counts for each tool
    local extracted_files_count=$(find "$output_directory" -type f | wc -l)
    local binwalk_count=$(find "$output_directory/binwalk" -type f | wc -l) # Modify the path as per your directory structure
    local bulk_extractor_count=$(find "$output_directory/bulk_extractor" -type f | wc -l)
    local foremost_count=$(find "$output_directory/foremost" -type f | wc -l)
    local strings_count=$(wc -l < "$output_directory/strings_output.txt") # Modify as per your file location

    # File counts for forensics analysis data
    local exes_count=$(wc -l < "$current_directory/forensics_analysis_data/exes.txt")
    local passwds_count=$(wc -l < "$current_directory/forensics_analysis_data/passwds.txt")
    local usernames_count=$(wc -l < "$current_directory/forensics_analysis_data/usernames.txt")
    local volatility_count=$(find "$current_directory/forensics_analysis_data" -name 'volatility_*' -type f | wc -l)

    echo " "
    echo "===== REPORT ====="
    # Print the header to the terminal
    echo "[+] $current_date_time - Forensics Analysis for $file_name"
    echo "[+] Time of Analysis: $hours hours, $minutes minutes, $seconds seconds"
    echo "[+] Output Folder:"
    echo " -> [Extracted Files: $extracted_files_count] [Binwalk: $binwalk_count files] [Bulk Extractor: $bulk_extractor_count files] [Foremost: $foremost_count files] [Strings: $strings_count lines]"
    echo "Forensics Analysis Folder:"
    echo " -> [Exes: $exes_count lines] [Passwds:$passwds_count lines] [Usernames: $usernames_count lines] [Volatility: $volatility_count files]"
    
    # Generating unique report folder name
    local report_time=$(date +"%Y%m%d%H%M%S")  # YYYYMMDDHHMMSS format
    local report_folder_name="Report_$report_time"
    local report_directory="$current_directory/$report_folder_name"

    # Create the report directory
    mkdir -p "$report_directory"

    # Move the forensics_analysis_data and output folders to the report directory
    mv "$current_directory/forensics_analysis_data" "$report_directory/" > /dev/null 2>&1
    mv "$output_directory" "$report_directory/" > /dev/null 2>&1


    # Zip the report directory
    zip -r "${report_folder_name}.zip" "$report_folder_name" > /dev/null
    
    # Clean up by removing the report directory (since we now have the zipped version)
    rm -rf "$report_folder_name"

    # Print out the confirmation message
    echo "[+] Forensics analysis completed [${report_folder_name}.zip]"
}


# Call the functions
check_and_install
check_volatility
carve_data
find_pcap_files "$output_directory"
find_human_readable "$output_directory"
volatility_analysis
display_statistics





