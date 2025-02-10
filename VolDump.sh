#!/bin/bash

# -------------------------------------------------------------------
# Función para verificar si un comando (ejecutable) está instalado
# -------------------------------------------------------------------
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# -------------------------------------------------------------------
# Función para instalar dependencias en Linux
# (python2, python3 y paquetes requeridos)
# -------------------------------------------------------------------
install_dependencies_linux() {
    echo "[+] Instalando dependencias en Linux..."
    sudo apt-get update -qq
    sudo apt-get install -y git python2 python3 python3-pip libdistorm3-dev libssl-dev libffi-dev python-yara python-crypto >/dev/null 2>&1
    # Instalamos paquetes de Python3
    pip3 install distorm3 yara-python pycrypto >/dev/null 2>&1
}

# -------------------------------------------------------------------
# Función para instalar dependencias en Windows (solo muestra un mensaje)
# -------------------------------------------------------------------
install_dependencies_windows() {
    echo "[!] Por favor, instale manualmente Python 2 y/o Python 3 desde:"
    echo "    https://www.python.org/downloads/"
    exit 1
}

# -------------------------------------------------------------------
# Función para descargar e instalar (clonar) Volatility 2 y 3
# -------------------------------------------------------------------
install_volatility() {
    # Volatility 2
    if [[ ! -d "volatility" ]]; then
        echo "[*] Descargando Volatility 2..."
        if git clone https://github.com/volatilityfoundation/volatility.git; then
            echo "[*] Descarga de Volatility 2 completada."
        else
            echo "[!] Error al descargar Volatility 2."
        fi
    else
        echo "[*] Volatility 2 ya está descargado."
    fi

    # Volatility 3
    if [[ ! -d "volatility3" ]]; then
        echo "[*] Descargando Volatility 3..."
        if git clone https://github.com/volatilityfoundation/volatility3.git; then
            echo "[*] Descarga de Volatility 3 completada."
        else
            echo "[!] Error al descargar Volatility 3."
        fi
    else
        echo "[*] Volatility 3 ya está descargado."
    fi
}


# -------------------------------------------------------------------
# Función para mostrar el banner
# -------------------------------------------------------------------
display_banner() {
    echo "=========================================="
    echo " VOLDUMP - Volatility 2 and Volatility 3 "
    echo "=========================================="       
    echo "---- By: MARH ----------------------------"
}

# -------------------------------------------------------------------
# Función para elegir la versión de Volatility
# -------------------------------------------------------------------
choose_volatility_version() {
    while true; do
        read -p "[+] Seleccione la versión de Volatility (2/3): " choice
        case $choice in
            2) echo "2"; return ;;
            3) echo "3"; return ;;
            *) echo "[-] Opción no válida. Intente de nuevo." ;;
        esac
    done
}

# -------------------------------------------------------------------
# Función para elegir el tipo de análisis
# -------------------------------------------------------------------
choose_analysis_type() {
    while true; do
        echo ""
        echo "Seleccione el tipo de análisis:"
        echo "  (1) Volcado de memoria existente"
        echo "  (2) Análisis en vivo del sistema actual"
        read -p "[+] Opción (1/2): " choice
        case $choice in
            1) echo "dump"; return ;;
            2) echo "live"; return ;;
            *) echo "[-] Opción no válida. Intente de nuevo." ;;
        esac
    done
}

# -------------------------------------------------------------------
# Función para preguntarle al usuario la ruta donde se guardarán las evidencias
# -------------------------------------------------------------------
get_evidence_path() {
    read -p "[+] Ingrese la ruta donde se guardarán las evidencias: " evidence_base_path
    # Si el usuario no ingresa nada, usar el directorio actual
    if [[ -z "$evidence_base_path" ]]; then
        evidence_base_path="."
    fi
    echo "$evidence_base_path"
}

# -------------------------------------------------------------------
# Función para crear carpeta de evidencias organizada
# -------------------------------------------------------------------
create_evidence_folder() {
    local base_path="$1"
    local date_time
    date_time=$(date +"%Y%m%d_%H%M%S")
    local evidence_folder="$base_path/Evidencias_$date_time"

    mkdir -p "$evidence_folder/Red"
    mkdir -p "$evidence_folder/Sistema"
    mkdir -p "$evidence_folder/Logs"
    mkdir -p "$evidence_folder/Procesos"
    mkdir -p "$evidence_folder/Otros"

    echo "$evidence_folder"
}

# -------------------------------------------------------------------
# Función para ejecutar los comandos de Volatility, 
# clasificándolos en carpetas según su naturaleza.
# -------------------------------------------------------------------
run_volatility_commands() {
    local volatility_version="$1"
    local analysis_type="$2"
    local evidence_path="$3"
    local memory_dump_path="$4"

    # Comandos Volatility 2
    local commands_vol2=(
        "pslist"
        "pstree"
        "psscan"
        "filescan"
        "dumpfiles"
        "hashdump"
        "netscan"
        "connections"
        "getsids"
        "lsa_secrets"
        "cachedump"
        "memmap"
        "vadinfo"
        "vaddump"
        "malfind"
        "apihooks"
        "ssdt"
        "idt"
        "modscan"
        "devicetree"
        "cmdline"
        "handles"
    )

    # Comandos Volatility 3 (para Linux se usan prefijos linux.*, para Windows windows.*)
    local commands_vol3=(
        "linux.pslist"
        "linux.pstree"
        "linux.psscan"
        "linux.filescan"
        "linux.dumpfiles"
        "linux.hashdump"
        "linux.netscan"
        "linux.connections"
        "linux.cachedump"
        "linux.vadinfo"
        "linux.memmap"
        "linux.malfind"
        "linux.ssdt"
        "linux.idt"
        "linux.cmdline"
        "linux.handles"
    )

    # Mapeo (asociamos cada comando con la carpeta destino)
    declare -A folder_map_vol2=(
        [pslist]="Procesos"
        [pstree]="Procesos"
        [psscan]="Procesos"
        [handles]="Procesos"

        [netscan]="Red"
        [connections]="Red"

        [lsa_secrets]="Sistema"
        [cachedump]="Sistema"
        [hashdump]="Sistema"
        [getsids]="Sistema"
        [apihooks]="Sistema"
        [ssdt]="Sistema"
        [idt]="Sistema"
        [modscan]="Sistema"
        [devicetree]="Sistema"

        [filescan]="Logs"
        [dumpfiles]="Logs"
        [malfind]="Logs"
        [memmap]="Logs"
        [vadinfo]="Logs"
        [vaddump]="Logs"
        [cmdline]="Logs"
    )

    declare -A folder_map_vol3=(
        ["linux.pslist"]="Procesos"
        ["linux.pstree"]="Procesos"
        ["linux.psscan"]="Procesos"
        ["linux.handles"]="Procesos"

        ["linux.netscan"]="Red"
        ["linux.connections"]="Red"

        ["linux.hashdump"]="Sistema"
        ["linux.cachedump"]="Sistema"
        ["linux.ssdt"]="Sistema"
        ["linux.idt"]="Sistema"

        ["linux.filescan"]="Logs"
        ["linux.dumpfiles"]="Logs"
        ["linux.malfind"]="Logs"
        ["linux.memmap"]="Logs"
        ["linux.vadinfo"]="Logs"
        ["linux.cmdline"]="Logs"
    )

    local vol_cmd
    local commands_to_run=()

    # Según la versión elegida, definimos el ejecutable y la lista de comandos
    if [[ "$volatility_version" == "2" ]]; then
        vol_cmd="./volatility/vol.py"
        commands_to_run=("${commands_vol2[@]}")
    else
        vol_cmd="./volatility3/vol.py"
        commands_to_run=("${commands_vol3[@]}")
    fi

    # Ejecutar cada comando y guardar en la carpeta correspondiente
    for cmd in "${commands_to_run[@]}"; do

        local folder="Otros"
        if [[ "$volatility_version" == "2" ]]; then
            folder="${folder_map_vol2[$cmd]}"
        else
            folder="${folder_map_vol3[$cmd]}"
        fi

        # Si no hay carpeta mapeada, se usará "Otros"
        if [[ -z "$folder" ]]; then
            folder="Otros"
        fi

        # Construir la ruta de salida
        local output_file="$evidence_path/$folder/${cmd}.txt"

        # Ejecutar Volatility (con volcado o en vivo)
        if [[ "$analysis_type" == "dump" ]]; then
            "$vol_cmd" -f "$memory_dump_path" $cmd > "$output_file" 2>/dev/null
        else
            "$vol_cmd" $cmd > "$output_file" 2>/dev/null
        fi

        echo "[*] Ejecutado: $cmd -> Guardado en '$folder/${cmd}.txt'"
        sleep 1  # Pausa de 1 segundo entre comandos (opcional)
    done
}

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
display_banner

# 1) Preguntamos la versión de Volatility que se desea utilizar
volatility_version=$(choose_volatility_version)

# 2) Verificamos que el Python requerido para esa versión esté instalado
if [[ "$volatility_version" == "2" ]]; then
    # Volatility 2 usa Python 2
    if ! is_installed "python2"; then
        echo "[-] Python 2 no está instalado en el sistema."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            install_dependencies_linux
        elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            install_dependencies_windows
        else
            echo "[-] Sistema operativo no compatible para instalación automática."
            exit 1
        fi
    fi
else
    # Volatility 3 usa Python 3
    if ! is_installed "python3"; then
        echo "[-] Python 3 no está instalado en el sistema."
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            install_dependencies_linux
        elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            install_dependencies_windows
        else
            echo "[-] Sistema operativo no compatible para instalación automática."
            exit 1
        fi
    fi
fi

# 3) Ahora que nos aseguramos de tener Python 2 o 3, instalamos Volatility si hace falta
install_volatility

# 4) Preguntamos el tipo de análisis
analysis_type=$(choose_analysis_type)

# 5) Obtenemos la ruta donde se guardarán las evidencias
evidence_base_path=$(get_evidence_path)

# 6) Creamos la carpeta de evidencias con subcarpetas
evidence_folder=$(create_evidence_folder "$evidence_base_path")

# 7) Si se eligió analizar un volcado, pedimos la ruta
memory_dump_path=""
if [[ "$analysis_type" == "dump" ]]; then
    read -p "[+] Ingrese la ruta del volcado de memoria (.raw, .mem, etc.): " memory_dump_path
    if [[ ! -f "$memory_dump_path" ]]; then
        echo "[-] Archivo no encontrado. Verifique la ruta y ejecute nuevamente."
        exit 1
    fi
fi

# 8) Ejecutamos los comandos de Volatility
run_volatility_commands "$volatility_version" "$analysis_type" "$evidence_folder" "$memory_dump_path"

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias:  ="
echo "=  $evidence_folder"
echo "============================================================================"
