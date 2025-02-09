#!/bin/bash

# Función para verificar si un comando está instalado
is_installed() {
    command -v $1 >/dev/null 2>&1
}

# Función para instalar dependencias según el sistema operativo
install_dependencies() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Instalando dependencias en Linux..."
        sudo apt-get update -y
        sudo apt-get install -y git python2 python3 python3-pip
        pip3 install distorm3 yara-python pycrypto
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        echo "[+] Instalando dependencias en Windows..."
        echo "Por favor, instale manualmente Python 2 y 3 desde https://www.python.org/downloads/"
        echo "Luego, instale las dependencias de Volatility usando pip:"
        echo "pip install distorm3 yara-python pycrypto"
        exit 1
    else
        echo "Sistema operativo no compatible."
        exit 1
    fi
}

# Función para instalar Volatility 2 y 3
install_volatility() {
    if [[ ! -d "volatility" ]]; then
        echo "[*] Descargando Volatility 2..."
        git clone https://github.com/volatilityfoundation/volatility.git &>/dev/null && echo "[*] Descarga completada"
    fi
    if [[ ! -d "volatility3" ]]; then
        echo "[*] Descargando Volatility 3..."
        git clone https://github.com/volatilityfoundation/volatility3.git &>/dev/null && echo "[*] Descarga completada"
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

# Función para mostrar el menú y obtener la opción del usuario
choose_option() {
    local prompt="$1"
    local options=($2)
    local choice
    while true; do
        echo "$prompt"
        for i in "${!options[@]}"; do
            echo "$((i+1)). ${options[$i]}"
        done
        read -p "Seleccione una opción: " choice
        if [[ "$choice" =~ ^[1-${#options[@]}]$ ]]; then
            echo "${options[$((choice-1))]}"
            return
        else
            echo "[-] Opción no válida, intente de nuevo."
        fi
    done
}

# Función para obtener la ruta del volcado de memoria
get_memory_dump_path() {
    local path
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
    local path
    read -p "[+] Ingrese la ruta donde desea guardar las evidencias: " path
    mkdir -p "$path"
    echo "$path"
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
volatility_version=$(choose_option "Seleccione la versión de Volatility:" "Volatility 2" "Volatility 3")

# Elegir tipo de análisis
analysis_type=$(choose_option "Seleccione el tipo de análisis:" "Analizar un volcado de memoria existente" "Realizar un análisis en vivo del sistema actual")

# Obtener ruta de evidencias
evidence_path=$(get_evidence_path)

# Obtener ruta del volcado de memoria si es necesario
memory_dump_path=""
if [[ "$analysis_type" == "Analizar un volcado de memoria existente" ]]; then
    memory_dump_path=$(get_memory_dump_path)
fi

# Ejecutar Volatility según la versión seleccionada
if [[ "$volatility_version" == "Volatility 2" ]]; then
    vol_cmd="./volatility/vol.py"
else
    vol_cmd="./volatility3/vol.py"
fi

# Mostrar resumen
echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias.  ="
echo "============================================================================"
