#!/bin/bash

# -------------------------------------------------------------------
# Volatility 3 Automation Script - Updated with Symbol Directory Support
# -------------------------------------------------------------------

# Display Banner
banner() {
    echo "=========================================="
    echo "      VOLDUMP - VOLATILITY 3              "
    echo "=========================================="
    echo "      By: MARH                           "
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
        os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" windows.info 2>/dev/null)
        [[ -n "$os_info" ]] && os_type="Windows"

        os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" linux.info 2>/dev/null)
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
    local symbols_path="$5"

    local commands_windows=("windows.pslist.PsList" "windows.pstree.PsTree" "windows.psscan.PsScan" "windows.filescan.FileScan" "windows.dumpfiles.DumpFiles" "windows.netscan.NetScan" "windows.netstat.NetStat" "windows.handles.Handles" "windows.cmdline.CmdLine" "windows.malfind.Malfind" "windows.vadinfo.VadInfo" "windows.ssdt.SSDT")

    local commands_linux=("linux.pslist.PsList" "linux.pstree.PsTree" "linux.psscan.PsScan" "linux.lsof.Lsof" "linux.mountinfo.MountInfo" "linux.netstat.Netstat" "linux.bash.Bash" "linux.proc.Maps" "linux.malfind.Malfind")

    declare -A folder_map=(
        [PsList]="Processes" [PsTree]="Processes" [PsScan]="Processes"
        [NetScan]="Network" [Netstat]="Network"
        [Handles]="System" [CmdLine]="System" [SSDT]="System"
        [FileScan]="Logs" [DumpFiles]="Logs" [Malfind]="Logs" [VadInfo]="Logs"
    )

    local commands_to_run=( )
    [[ "$os_type" == "Windows" ]] && commands_to_run=("${commands_windows[@]}") || commands_to_run=("${commands_linux[@]}")

    for cmd in "${commands_to_run[@]}"; do
        local cmd_short=$(echo $cmd | awk -F '.' '{print $NF}')
        local folder=${folder_map[$cmd_short]:-Other}
        local output_file="$evidence_path/$folder/${cmd_short}.txt"

        echo "[*] Running: $cmd..."
        local output=""
        if [[ "$analysis_type" == "dump" ]]; then
            output=$(python3 volatility3/vol.py -f "$memory_dump_path" --symbol-dirs "$symbols_path" "$cmd" 2>&1)
        else
            output=$(python3 volatility3/vol.py --symbol-dirs "$symbols_path" "$cmd" 2>&1)
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

read -p "[+] Enter the symbols directory path (press ENTER to skip): " symbols_path
[[ -z "$symbols_path" ]] && symbols_path="volatility3/symbols"

read -p "[+] Select analysis type (1) Memory Dump (2) Live System: " analysis_choice
case $analysis_choice in
    1)
        read -p "[+] Enter the memory dump path: " memory_dump_path
        os_type=$(identify_os "dump" "$memory_dump_path")
        run_volatility_commands "dump" "$evidence_folder" "$memory_dump_path" "$os_type" "$symbols_path"
        ;;
    2)
        os_type=$(identify_os "live")
        run_volatility_commands "live" "$evidence_folder" "" "$os_type" "$symbols_path"
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
