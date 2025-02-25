#!/bin/bash

# -------------------------------------------------------------------
# Función para verificar si un comando (ejecutable) está instalado
# -------------------------------------------------------------------
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# -------------------------------------------------------------------
# Función para instalar dependencias en Linux
# -------------------------------------------------------------------
install_dependencies_linux() {
    echo "[+] Instalando dependencias en Linux..."
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip git >/dev/null 2>&1
    echo "[+] Instalando Volatility 3..."
    if [[ ! -d "volatility3" ]]; then
        git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            cd volatility3 || { echo "[-] Error al cambiar al directorio volatility3"; exit 1; }
            pip3 install -r requirements.txt >/dev/null 2>&1
            cd ..
        else
            echo "[-] Error al clonar Volatility 3."
            exit 1
        fi
    else
        echo "[*] Volatility 3 ya está instalado."
    fi
}

# -------------------------------------------------------------------
# Función para mostrar el banner
# -------------------------------------------------------------------
display_banner() {
    echo "  __     __    _ ____                        "
    echo "  \ \   / /__ | |  _ \ _   _ _ __ ___  _ __  "
    echo "   \ \ / / _ \| | | | | | | | '_ \` _ \| '_ \ "
    echo "    \ V / (_) | | |_| | |_| | | | | | | |_) |"
    echo "     \_/ \___/|_|____/ \__,_|_| |_| |_| .__/ "
    echo "                                      |_|    "
    echo "---- By: MARH -------------------------------"
}

# -------------------------------------------------------------------
# Función para verificar la instalación
# -------------------------------------------------------------------
check_installation() {
    is_installed "python3" && echo "[*] Python 3 está instalado." || echo "[-] Python 3 no está instalado."
    [[ -d "volatility3" ]] && echo "[*] Volatility 3 está instalado." || echo "[-] Volatility 3 no está instalado."
}

# -------------------------------------------------------------------
# Función para elegir el tipo de análisis
# -------------------------------------------------------------------
choose_analysis_type() {
    while true; do
        echo ""
        echo "Seleccione el tipo de análisis:"
        read -p "[+] (1) Volcado de memoria existente (2) Análisis en vivo del sistema actual (1/2): " choice
        case $choice in
            1) echo "dump"; return ;;
            2) echo "live"; return ;;
            *) echo "[-] Opción no válida. Intente de nuevo." ;;
        esac
    done
}

# -------------------------------------------------------------------
# Obtener la ruta de evidencias
# -------------------------------------------------------------------
get_evidence_path() {
    read -p "[+] Ingrese la ruta donde se guardarán las evidencias (ENTER para actual): " evidence_base_path
    [[ -z "$evidence_base_path" ]] && evidence_base_path="."
    echo "$evidence_base_path"
}

# -------------------------------------------------------------------
# Crear carpeta de evidencias
# -------------------------------------------------------------------
create_evidence_folder() {
    local base_path="$1"
    local date_time=$(date +"%Y%m%d_%H%M%S")
    local evidence_folder="$base_path/Evidencias_$date_time"

    mkdir -p "$evidence_folder/Red" "$evidence_folder/Sistema" "$evidence_folder/Logs" "$evidence_folder/Procesos" "$evidence_folder/Otros"
    echo "$evidence_folder"
}

# -------------------------------------------------------------------
# Identificar el sistema operativo
# -------------------------------------------------------------------
identify_os() {
    local analysis_type="$1"
    local memory_dump_path="$2"
    echo "[+] Identificando el sistema operativo..."
    if [[ "$analysis_type" == "dump" ]]; then
        os_info=$(python3 -m volatility3.vol -f "$memory_dump_path" windows.info 2>/dev/null | grep "OS")
        [[ -n "$os_info" ]] && echo "windows" && return

        os_info=$(python3 -m volatility3.vol -f "$memory_dump_path" linux.banner 2>/dev/null)
        [[ -n "$os_info" ]] && echo "linux" && return

        echo "[-] No se pudo identificar el sistema operativo." && exit 1
    else
        [[ "$OSTYPE" == "linux-gnu"* ]] && echo "linux" || echo "windows"
    fi
}

# -------------------------------------------------------------------
# Ejecutar todos los comandos de Volatility 3
# -------------------------------------------------------------------
run_volatility_commands() {
    local analysis_type="$1"
    local evidence_path="$2"
    local memory_dump_path="$3"
    local os_type="$4"

    # Comandos para Windows
    local commands_windows=(
        "windows.pslist" "windows.pstree" "windows.psscan" "windows.filescan"
        "windows.dumpfiles" "windows.hashdump" "windows.netscan" "windows.connections"
        "windows.cachedump" "windows.vadinfo" "windows.memmap" "windows.malfind"
        "windows.ssdt" "windows.idt" "windows.cmdline" "windows.handles"
    )

    # Comandos para Linux
    local commands_linux=(
        "linux.pslist" "linux.pstree" "linux.psscan" "linux.filescan"
        "linux.dumpfiles" "linux.bash" "linux.check_syscall" "linux.lsof"
        "linux.netstat" "linux.proc_maps" "linux.malfind" "linux.mountinfo"
    )

    # Mapeo de carpetas
    declare -A folder_map=(
        [pslist]="Procesos" [pstree]="Procesos" [psscan]="Procesos" [handles]="Procesos"
        [netscan]="Red" [connections]="Red"
        [hashdump]="Sistema" [cachedump]="Sistema" [ssdt]="Sistema" [idt]="Sistema"
        [filescan]="Logs" [dumpfiles]="Logs" [malfind]="Logs" [memmap]="Logs" [vadinfo]="Logs" [cmdline]="Logs"
    )

    # Selección de comandos según SO
    local commands_to_run=( )
    [[ "$os_type" == "windows" ]] && commands_to_run=("${commands_windows[@]}") || commands_to_run=("${commands_linux[@]}")

    # Ejecutar comandos
    cd volatility3 || { echo "[-] Error: No se encuentra la carpeta volatility3"; exit 1; }
    for cmd in "${commands_to_run[@]}"; do
        local cmd_short=$(echo $cmd | cut -d. -f2)
        local folder=${folder_map[$cmd_short]:-Otros}
        local output_file="$evidence_path/$folder/${cmd_short}.txt"

        echo "[*] Ejecutando: $cmd..."
        output=""
        if [[ "$analysis_type" == "dump" ]]; then
            output=$(python3 -m volatility3.vol -f "$memory_dump_path" "$cmd" 2>/dev/null)
        else
            output=$(python3 -m volatility3.vol "$cmd" 2>/dev/null)
        fi

        if [[ -n "$output" ]]; then
            echo "$output" > "$output_file"
            echo "[+] Guardado en '$folder/${cmd_short}.txt'"
        else
            echo "[!] Sin salida para $cmd"
        fi
    done
    cd ..
}

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
display_banner

check_installation

if ! is_installed "python3" || [[ ! -d "volatility3" ]]; then
    [[ "$OSTYPE" == "linux-gnu"* ]] && install_dependencies_linux || { echo "[-] Instalación automática no soportada en este sistema."; exit 1; }
fi

analysis_type=$(choose_analysis_type)
evidence_base_path=$(get_evidence_path)
evidence_folder=$(create_evidence_folder "$evidence_base_path")

memory_dump_path=""
if [[ "$analysis_type" == "dump" ]]; then
    read -p "[+] Ruta del volcado de memoria: " memory_dump_path
    [[ ! -f "$memory_dump_path" ]] && echo "[-] Archivo no encontrado." && exit 1
fi

os_type=$(identify_os "$analysis_type" "$memory_dump_path")

run_volatility_commands "$analysis_type" "$evidence_folder" "$memory_dump_path" "$os_type"

echo "============================================================================"
echo " Análisis completado. Resultados guardados en: "
echo "  $evidence_folder"
echo "============================================================================"
