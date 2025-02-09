#!/bin/bash

# Función para verificar si un comando está instalado
is_installed() {
    command -v $1 >/dev/null 2>&1
}

# Función para instalar dependencias según el sistema operativo
install_dependencies() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "[+] Instalando dependencias en Linux..."
        sudo apt-get update
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

# Función para clonar Volatility 2 y 3
install_volatility() {
    if [[ ! -d "volatility" ]]; then
        git clone https://github.com/volatilityfoundation/volatility.git
    fi
    if [[ ! -d "volatility3" ]]; then
        git clone https://github.com/volatilityfoundation/volatility3.git
    fi
}

# Función para preguntar al usuario
ask_user() {
    read -p "$1 (s/n): " choice
    [[ "$choice" == "s" ]]
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

# Función para crear directorios de evidencias
create_evidence_directories() {
    base_path=$1
    timestamp=$(date +"%Y%m%d_%H%M%S")
    main_folder="$base_path/Evidencias_$timestamp"
    mkdir -p "$main_folder"

    categories=("Información_General" "Procesos_y_Módulos" "Archivos_y_Registro" "Red_y_Conexiones" "Usuarios_y_Credenciales" "Malware_y_Rootkits" "Otros_Comandos_Útiles")
    declare -A category_paths

    for category in "${categories[@]}"; do
        category_paths["$category"]="$main_folder/$category"
        mkdir -p "${category_paths[$category]}"
    done

    echo "${category_paths[@]}"
}

# Función para obtener todos los comandos de Volatility
get_volatility_commands() {
    volatility_version=$1
    if [[ "$volatility_version" == "2" ]]; then
        volatility_path="./volatility/vol.py"
    else
        volatility_path="./volatility3/vol.py"
    fi

    # Obtener la lista de comandos disponibles
    commands=$($volatility_path --help | grep -oP '^\s+\K\w+')
    echo "$commands"
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

    # Obtener todos los comandos de Volatility
    commands=$(get_volatility_commands "$volatility_version")

    # Crear directorios de evidencias
    paths=($(create_evidence_directories "$evidence_path"))

    # Ejecutar cada comando y guardar los resultados
    for cmd in $commands; do
        output_file="$evidence_path/Evidencias_$(date +"%Y%m%d_%H%M%S")/${cmd// /_}.txt"
        if [[ "$analysis_type" == "dump" ]]; then
            $vol_cmd -f "$memory_dump_path" $cmd > "$output_file"
        else
            $vol_cmd $cmd > "$output_file"
        fi
        echo "Comando ejecutado: $cmd"
    done
}

# Main
display_banner

# Verificar e instalar dependencias
if ! is_installed "python2" || ! is_installed "python3"; then
    echo "[-] Python 2 o Python 3 no están instalados."
    if ask_user "¿Desea instalarlos? (s/n): "; then
        install_dependencies
    else
        echo "Python 2 y 3 son necesarios para usar esta herramienta."
        exit 1
    fi
fi

# Instalar Volatility si no está instalado
if [[ ! -d "volatility" || ! -d "volatility3" ]]; then
    echo "[-] Volatility no está instalado."
    if ask_user "¿Desea instalarlo? (s/n): "; then
        install_volatility
    else
        echo "Volatility es necesario para usar esta herramienta."
        exit 1
    fi
fi

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

# Ejecutar comandos de Volatility
run_volatility_commands "$volatility_version" "$analysis_type" "$evidence_path" "$memory_dump_path"
echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias.  ="
echo "============================================================================"