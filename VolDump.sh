#!/bin/bash

# Función para verificar si un comando está instalado
is_installed() {
    command -v $1 >/dev/null 2>&1
}

# Función para instalar dependencias
install_dependencies() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Instalando dependencias en Linux..."
        sudo apt-get update -qq
        sudo apt-get install -y git python2 python3 python3-pip >/dev/null 2>&1
        pip3 install distorm3 yara-python pycrypto >/dev/null 2>&1
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "Por favor, instale manualmente Python 2 y 3 desde https://www.python.org/downloads/"
        exit 1
    else
        echo "Sistema operativo no compatible."
        exit 1
    fi
}

# Función para clonar Volatility
install_volatility() {
    if [[ ! -d "volatility" ]]; then
        echo "[*] Descargando Volatility 2..."
        git clone https://github.com/volatilityfoundation/volatility.git >/dev/null 2>&1 && echo "[*] Descarga completada"
    fi
    if [[ ! -d "volatility3" ]]; then
        echo "[*] Descargando Volatility 3..."
        git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1 && echo "[*] Descarga completada"
    fi
}

# Función para mostrar el banner
display_banner() {
    cat << "EOF"
    __      __   _ _____                         
    \ \    / /  | |  __ \                       
     \ \  / /__ | | |  | |_   _ _ __ ___  _ __  
      \ \/ / _ \| | |  | | | | | '_ ` _ \| '_ \ 
       \  / (_) | | |__| | |_| | | | | | | |_) |
        \/ \___/|_|_____/ \__,_|_| |_| |_| .__/ 
                                         | |    
                                         |_|   
    ---- By: MARH ------------------------------
EOF
}

# Función para elegir la versión de Volatility
choose_volatility_version() {
    while true; do
        echo "====================="
        echo "=  1. Volatility 2  ="
        echo "=  2. Volatility 3  ="
        echo "====================="
        read -p "Seleccione la versión de Volatility: " choice
        case $choice in
            1) echo "2"; return ;;  # Retorna "2" para Volatility 2
            2) echo "3"; return ;;  # Retorna "3" para Volatility 3
            *) echo "[-] Opción no válida, intente de nuevo." ;;
        esac
    done
}

# Función para elegir el tipo de análisis
choose_analysis_type() {
    while true; do
        echo "=========================================================="
        echo "=   1. Analizar un volcado de memoria existente          ="
        echo "=   2. Realizar un análisis en vivo del sistema actual   ="
        echo "=========================================================="
        read -p "Seleccione el tipo de análisis: " choice
        case $choice in
            1) echo "dump"; return ;;  # Retorna "dump" para análisis de volcado de memoria
            2) echo "live"; return ;;  # Retorna "live" para análisis en vivo
            *) echo "[-] Opción no válida, intente de nuevo." ;;
        esac
    done
}

# Función para obtener la ruta de almacenamiento de evidencias
get_evidence_path() {
    read -p "[+] Ingrese la ruta donde desea guardar las evidencias: " path
    mkdir -p "$path"
    echo "$path"
}

# Función para obtener todos los comandos de Volatility
get_volatility_commands() {
    volatility_version=$1
    if [[ "$volatility_version" == "2" ]]; then
        volatility_path="./volatility/vol.py"
    else
        volatility_path="./volatility3/vol.py"
    fi
    
    $volatility_path --info | awk '/^Plugin Name:/ {print $3}'
}

# Función para ejecutar comandos de Volatility
run_volatility_commands() {
    volatility_version=$1
    analysis_type=$2
    evidence_path=$3
    memory_dump_path=$4
    
    if [[ "$volatility_version" == "2" ]]; then
        vol_cmd="./volatility/vol.py"
    else
        vol_cmd="./volatility3/vol.py"
    fi
    
    commands=$(get_volatility_commands "$volatility_version")
    
    for cmd in $commands; do
        output_file="$evidence_path/${cmd}.txt"
        if [[ "$analysis_type" == "dump" ]]; then
            $vol_cmd -f "$memory_dump_path" $cmd > "$output_file" 2>/dev/null
        else
            $vol_cmd $cmd > "$output_file" 2>/dev/null
        fi
        echo "[*] Ejecutado: $cmd"
        sleep 1  # Pausa de 1 segundo entre comandos
    done
}

# Main
display_banner

# Verificar Python 2 y 3
if ! is_installed "python2" || ! is_installed "python3"; then
    echo "[-] Python 2 o Python 3 no están instalados."
    install_dependencies
fi

# Verificar e instalar Volatility
install_volatility

# Elegir versión de Volatility
volatility_version=$(choose_volatility_version)

# Elegir tipo de análisis
analysis_type=$(choose_analysis_type)

# Obtener ruta de evidencias
evidence_path=$(get_evidence_path)

# Obtener ruta del volcado de memoria si es necesario
memory_dump_path=""
if [[ "$analysis_type" == "dump" ]]; then
    read -p "[+] Ingrese la ruta del volcado de memoria: " memory_dump_path
    if [[ ! -f "$memory_dump_path" ]]; then
        echo "[-] Archivo no encontrado, intente de nuevo."
        exit 1
    fi
fi

# Ejecutar comandos de Volatility
run_volatility_commands "$volatility_version" "$analysis_type" "$evidence_path" "$memory_dump_path"

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias.  ="
echo "============================================================================"
