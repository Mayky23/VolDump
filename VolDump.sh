#!/bin/bash

# -------------------------------------------------------------------
# Volatility 3 Automation Script - Optimized with Correct Execution
# -------------------------------------------------------------------

# Display Banner
banner() {
    echo "=========================================="
    echo "   VOLDUMP VOLATILITY 3 AUTOMATION TOOL   "
    echo "=========================================="
    echo "   By: MARH                               "
    echo "=========================================="
}

# Check if a command is installed
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# Install dependencies on Linux
install_dependencies_linux() {
    echo "[+] Installing dependencies on Linux..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip git >/dev/null 2>&1

    echo "[+] Installing Volatility 3..."
    if [[ ! -d "volatility3" ]]; then
        git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1
        cd volatility3 || exit 1
        pip3 install -r requirements.txt >/dev/null 2>&1
        cd ..
    else
        echo "[*] Volatility 3 is already installed."
    fi
}

# Verify installations
check_installation() {
    is_installed "python3" && echo "[*] Python 3 is installed." || echo "[-] Python 3 is not installed."
    [[ -d "volatility3" ]] && echo "[*] Volatility 3 is installed." || echo "[-] Volatility 3 is not installed."
}

# Create evidence folders
create_evidence_folder() {
    local base_path="$1"
    local date_time=$(date +"%Y%m%d_%H%M%S")
    local evidence_folder="$base_path/Evidences_$date_time"

    for folder in "Network" "System" "Logs" "Processes" "Other"; do
        mkdir -p "$evidence_folder/$folder" || exit 1
    done
    echo "$evidence_folder"
}

# Identify the operating system of the target
identify_os() {
    local analysis_type="$1"
    local memory_dump_path="$2"
    local os_type=""

    echo "[+] Detecting the operating system of the target..."

    if [[ "$analysis_type" == "dump" ]]; then
        os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" windows.info 2>/dev/null | grep "OS")
        [[ -n "$os_info" ]] && os_type="Windows"

        os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" linux.banner 2>/dev/null)
        [[ -n "$os_info" ]] && os_type="Linux"

        if [[ -z "$os_type" ]]; then
            echo "[!] Unable to detect the OS. Please verify the dump file."
            exit 1
        fi
    else
        [[ "$OSTYPE" == "linux-gnu"* ]] && os_type="Linux" || os_type="Windows"
    fi

    echo "[*] TARGET OPERATING SYSTEM DETECTED: $os_type"
    echo "$os_type"
}

# Run Volatility 3 commands
run_volatility_commands() {
    local analysis_type="$1"
    local evidence_path="$2"
    local memory_dump_path="$3"
    local os_type="$4"

    local commands_windows=("windows.pslist" "windows.pstree" "windows.psscan" "windows.filescan" "windows.dumpfiles" "windows.hashdump" "windows.netscan" "windows.connections" "windows.cachedump" "windows.vadinfo" "windows.memmap" "windows.malfind" "windows.ssdt" "windows.idt" "windows.cmdline" "windows.handles")
    local commands_linux=("linux.pslist" "linux.pstree" "linux.psscan" "linux.filescan" "linux.dumpfiles" "linux.bash" "linux.check_syscall" "linux.lsof" "linux.netstat" "linux.proc_maps" "linux.malfind" "linux.mountinfo")

    declare -A folder_map=(
        [pslist]="Processes" [pstree]="Processes" [psscan]="Processes" [handles]="Processes"
        [netscan]="Network" [connections]="Network"
        [hashdump]="System" [cachedump]="System" [ssdt]="System" [idt]="System"
        [filescan]="Logs" [dumpfiles]="Logs" [malfind]="Logs" [memmap]="Logs" [vadinfo]="Logs" [cmdline]="Logs"
    )

    local commands_to_run=( )
    [[ "$os_type" == "Windows" ]] && commands_to_run=("${commands_windows[@]}") || commands_to_run=("${commands_linux[@]}")

    for cmd in "${commands_to_run[@]}"; do
        local cmd_short=$(echo $cmd | cut -d. -f2)
        local folder=${folder_map[$cmd_short]:-Other}
        local output_file="$evidence_path/$folder/${cmd_short}.txt"

        echo "[*] Running: $cmd..."
        local output=""
        if [[ "$analysis_type" == "dump" ]]; then
            output=$(python3 volatility3/vol.py -f "$memory_dump_path" "$cmd" 2>&1)
        else
            output=$(python3 volatility3/vol.py "$cmd" 2>&1)
        fi

        if [[ -n "$output" ]]; then
            echo "$output" > "$output_file"
            echo "[+] Saved at '$output_file'"
        else
            echo "[!] No output for $cmd"
        fi
    done
}

# Main script
banner

if ! is_installed "python3" || [[ ! -d "volatility3" ]]; then
    install_dependencies_linux
fi

check_installation

read -p "[+] Enter the evidence folder path (press ENTER for current directory): " evidence_base_path
[[ -z "$evidence_base_path" ]] && evidence_base_path="."
evidence_folder=$(create_evidence_folder "$evidence_base_path")

read -p "[+] Select analysis type (1) Memory Dump (2) Live System: " analysis_choice
case $analysis_choice in
    1)
        read -p "[+] Enter the memory dump path: " memory_dump_path
        os_type=$(identify_os "dump" "$memory_dump_path")
        run_volatility_commands "dump" "$evidence_folder" "$memory_dump_path" "$os_type"
        ;;
    2)
        os_type=$(identify_os "live")
        run_volatility_commands "live" "$evidence_folder" "" "$os_type"
        ;;
    *)
        echo "[-] Invalid option."
        exit 1
        ;;
esac

echo "============================================================================"
echo " Analysis completed. Results saved in: "
echo "  $evidence_folder"
echo "============================================================================"
