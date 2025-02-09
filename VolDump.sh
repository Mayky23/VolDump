#!/bin/bash

# Función para verificar si un comando está instalado
is_installed() {
    command -v $1 >/dev/null 2>&1
}

# Función para instalar dependencias según el sistema operativo
install_dependencies() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Instalando dependencias en Linux..."
        sudo apt-get update -y >/dev/null 2>&1
        sudo apt-get install -y git python2 python3 python3-pip >/dev/null 2>&1
        pip3 install distorm3 yara-python pycrypto >/dev/null 2>&1
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "[+] Instalando dependencias en Windows..."
        echo "Por favor, instale manualmente Python 2 y 3 desde https://www.python.org/downloads/"
        echo "Luego, instale las dependencias de Volatility usando pip:"
        echo "pip install distorm3 yara-python pycrypto"
        exit 1
    else
        echo "[-] Sistema operativo no compatible."
        exit 1
    fi
}

# Función para instalar Volatility 2 y 3
install_volatility() {
    if [[ ! -d "volatility" ]]; then
        echo "[*] Descargando Volatility 2..."
        git clone https://github.com/volatilityfoundation/volatility.git >/dev/null 2>&1
    fi
    if [[ ! -d "volatility3" ]]; then
        echo "[*] Descargando Volatility 3..."
        git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1
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
        if [[ "$choice" == "1" || "$choice" == "2" ]]; then
            echo "$choice"
            return
        fi
        echo "[-] Opción no válida, intente de nuevo."
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
        if [[ "$choice" == "1" || "$choice" == "2" ]]; then
            [[ "$choice" == "1" ]] && echo "dump" || echo "live"
            return
        fi
        echo "[-] Opción no válida, intente de nuevo."
    done
}

# Función para obtener la ruta del volcado de memoria
get_memory_dump_path() {
    while true; do
        read -p "[+] Ingrese la ruta del volcado de memoria: " path
        if [[ -f "$path" ]]; then
            echo "$path"
            return
        fi
        echo "[-] Archivo no encontrado, intente de nuevo."
    done
}

# Función para obtener la ruta donde guardar las evidencias
get_evidence_path() {
    while true; do
        read -p "[+] Ingrese la ruta donde desea guardar las evidencias: " path
        mkdir -p "$path"
        echo "$path"
        return
    done
}

# Main
display_banner

# Verificar e instalar dependencias
if ! is_installed "python2" || ! is_installed "python3"; then
    echo "[-] Python 2 o Python 3 no están instalados."
    install_dependencies
fi

# Instalar Volatility si no está instalado
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
    memory_dump_path=$(get_memory_dump_path)
fi

# Definir la ruta de ejecución según la versión
declare -A volatility_paths
volatility_paths["2"]="./volatility/vol.py"
volatility_paths["3"]="./volatility3/vol.py"
vol_cmd=${volatility_paths[$volatility_version]}

# Verificar si el archivo de Volatility existe
if [[ ! -f "$vol_cmd" ]]; then
    echo "[-] Error: No se encontró el ejecutable de Volatility en la ruta esperada."
    exit 1
fi

# Ejecutar análisis
echo "[*] Ejecutando análisis con Volatility $volatility_version..."
if [[ "$analysis_type" == "dump" ]]; then
    $vol_cmd -f "$memory_dump_path" --help
else
    $vol_cmd --help
fi

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias.  ="
echo "============================================================================"
