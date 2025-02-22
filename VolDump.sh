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
# Función para instalar dependencias en Windows (solo muestra un mensaje)
# -------------------------------------------------------------------
install_dependencies_windows() {
    echo "[!] Por favor, instale manualmente Python 3 desde:"
    echo "    https://www.python.org/downloads/"
    echo "[!] Luego, clone el repositorio de Volatility 3 y ejecute:"
    echo "    pip install -r requirements.txt"
    exit 1
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
    echo "============================================="
    echo " VOLDUMP - Volatility 3 Memory Analysis      "
    echo "============================================="
    echo "---- By: MARH -------------------------------"
}

# -------------------------------------------------------------------
# Función para verificar si Python 3 y Volatility 3 están instalados
# -------------------------------------------------------------------
check_installation() {
    if is_installed "python3"; then
        echo "[*] Python 3 está instalado."
    else
        echo "[-] Python 3 no está instalado."
    fi

    if [[ -d "volatility3" ]]; then
        echo "[*] Volatility 3 está instalado."
    else
        echo "[-] Volatility 3 no está instalado."
    fi
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

    # Crear las carpetas necesarias
    mkdir -p "$evidence_folder/Red" && echo "Carpeta Red creada"
    mkdir -p "$evidence_folder/Sistema" && echo "Carpeta Sistema creada"
    mkdir -p "$evidence_folder/Logs" && echo "Carpeta Logs creada"
    mkdir -p "$evidence_folder/Procesos" && echo "Carpeta Procesos creada"
    mkdir -p "$evidence_folder/Otros" && echo "Carpeta Otros creada"

    echo "$evidence_folder"
}

# -------------------------------------------------------------------
# Función para identificar el sistema operativo del volcado o sistema en vivo
# -------------------------------------------------------------------
identify_os() {
    local analysis_type="$1"
    local memory_dump_path="$2"

    echo "[+] Identificando el sistema operativo..."

    if [[ "$analysis_type" == "dump" ]]; then
        # Usamos el comando 'windows.info' de Volatility 3 para identificar el sistema operativo
        os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" windows.info 2>/dev/null | grep "OS")
        if [[ -n "$os_info" ]]; then
            echo "[*] Sistema operativo identificado: Windows"
            echo "windows"
        else
            os_info=$(python3 volatility3/vol.py -f "$memory_dump_path" linux.banner 2>/dev/null)
            if [[ -n "$os_info" ]]; then
                echo "[*] Sistema operativo identificado: Linux"
                echo "linux"
            else
                echo "[-] No se pudo identificar el sistema operativo."
                exit 1
            fi
        fi
    else
        # Análisis en vivo: asumimos que el sistema actual es el que se está analizando
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            echo "[*] Sistema operativo identificado: Linux (sistema actual)"
            echo "linux"
        elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            echo "[*] Sistema operativo identificado: Windows (sistema actual)"
            echo "windows"
        else
            echo "[-] No se pudo identificar el sistema operativo."
            exit 1
        fi
    fi
}

# -------------------------------------------------------------------
# Función para ejecutar los comandos de Volatility 3
# -------------------------------------------------------------------
run_volatility_commands() {
    local analysis_type="$1"
    local evidence_path="$2"
    local memory_dump_path="$3"
    local os_type="$4"

    # Comandos Volatility 3 para Windows
    local commands_windows=(
        "windows.pslist"
        "windows.pstree"
        "windows.psscan"
        "windows.filescan"
        "windows.dumpfiles"
        "windows.hashdump"
        "windows.netscan"
        "windows.connections"
        "windows.cachedump"
        "windows.vadinfo"
        "windows.memmap"
        "windows.malfind"
        "windows.ssdt"
        "windows.idt"
        "windows.cmdline"
        "windows.handles"
    )

    # Comandos Volatility 3 para Linux
    local commands_linux=(
        "linux.pslist"
        "linux.pstree"
        "linux.psscan"
        "linux.filescan"
        "linux.dumpfiles"
        "linux.bash"
        "linux.check_syscall"
        "linux.lsof"
        "linux.netstat"
        "linux.proc_maps"
        "linux.malfind"
        "linux.mountinfo"
    )

    # Mapeo de comandos a carpetas (para Windows y Linux)
    declare -A folder_map_windows=(
        ["windows.pslist"]="Procesos"
        ["windows.pstree"]="Procesos"
        ["windows.psscan"]="Procesos"
        ["windows.handles"]="Procesos"

        ["windows.netscan"]="Red"
        ["windows.connections"]="Red"

        ["windows.hashdump"]="Sistema"
        ["windows.cachedump"]="Sistema"
        ["windows.ssdt"]="Sistema"
        ["windows.idt"]="Sistema"

        ["windows.filescan"]="Logs"
        ["windows.dumpfiles"]="Logs"
        ["windows.malfind"]="Logs"
        ["windows.memmap"]="Logs"
        ["windows.vadinfo"]="Logs"
        ["windows.cmdline"]="Logs"
    )

    declare -A folder_map_linux=(
        ["linux.pslist"]="Procesos"
        ["linux.pstree"]="Procesos"
        ["linux.psscan"]="Procesos"

        ["linux.netstat"]="Red"

        ["linux.bash"]="Sistema"
        ["linux.check_syscall"]="Sistema"
        ["linux.mountinfo"]="Sistema"

        ["linux.filescan"]="Logs"
        ["linux.dumpfiles"]="Logs"
        ["linux.lsof"]="Logs"
        ["linux.proc_maps"]="Logs"
        ["linux.malfind"]="Logs"
    )

    # Seleccionar comandos y mapeo según el sistema operativo
    if [[ "$os_type" == "windows" ]]; then
        commands_to_run=("${commands_windows[@]}")
        folder_map=("${folder_map_windows[@]}")
    else
        commands_to_run=("${commands_linux[@]}")
        folder_map=("${folder_map_linux[@]}")
    fi

    # Ejecutar cada comando y guardar en la carpeta correspondiente
    for cmd in "${commands_to_run[@]}"; do
        local folder="Otros"
        folder="${folder_map[$cmd]}"

        # Si no hay carpeta mapeada, se usará "Otros"
        if [[ -z "$folder" ]]; then
            folder="Otros"
        fi

        # Construir la ruta de salida
        local output_file="$evidence_path/$folder/${cmd}.txt"

        # Ejecutar Volatility (con volcado o en vivo)
        if [[ "$analysis_type" == "dump" ]]; then
            output=$(python3 volatility3/vol.py -f "$memory_dump_path" $cmd 2>/dev/null)
        else
            output=$(python3 volatility3/vol.py $cmd 2>/dev/null)
        fi

        # Si hay salida, guardamos el archivo
        if [[ -n "$output" ]]; then
            echo "$output" > "$output_file"
            echo "[*] Ejecutado: $cmd -> Guardado en '$folder/${cmd}.txt'"
        else
            echo "[!] No se generó salida para el comando $cmd"
        fi

        sleep 3  # Pausa de 3 segundos entre comandos
    done
}

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
display_banner

# 1) Verificamos la instalación de Python 3 y Volatility 3
check_installation

# 2) Instalamos dependencias si es necesario
if ! is_installed "python3" || [[ ! -d "volatility3" ]]; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        install_dependencies_linux
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        install_dependencies_windows
    else
        echo "[-] Sistema operativo no compatible para instalación automática."
        exit 1
    fi
fi

# 3) Preguntamos el tipo de análisis
analysis_type=$(choose_analysis_type)

# 4) Obtenemos la ruta donde se guardarán las evidencias
evidence_base_path=$(get_evidence_path)

# 5) Creamos la carpeta de evidencias con subcarpetas
evidence_folder=$(create_evidence_folder "$evidence_base_path")

# 6) Si se eligió analizar un volcado, pedimos la ruta
memory_dump_path=""
if [[ "$analysis_type" == "dump" ]]; then
    read -p "[+] Ingrese la ruta del volcado de memoria (.raw, .mem, etc.): " memory_dump_path
    if [[ ! -f "$memory_dump_path" ]]; then
        echo "[-] Archivo no encontrado. Verifique la ruta y ejecute nuevamente."
        exit 1
    fi
fi

# 7) Identificamos el sistema operativo
os_type=$(identify_os "$analysis_type" "$memory_dump_path")

# 8) Ejecutamos los comandos de Volatility 3 según el sistema operativo
run_volatility_commands "$analysis_type" "$evidence_folder" "$memory_dump_path" "$os_type"

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias:  ="
echo "=  $evidence_folder"
echo "============================================================================"