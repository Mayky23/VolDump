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
        echo "====================="
        read -p "Seleccione la versión de Volatility (solo Volatility 2 disponible): " choice
        case $choice in
            1) echo "2"; return ;;
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
            1) echo "dump"; return ;;
            2) echo "live"; return ;;
            *) echo "[-] Opción no válida, intente de nuevo." ;;
        esac
    done
}

# Función para obtener la ruta de almacenamiento de evidencias
get_evidence_path() {
    current_time=$(date "+%Y%m%d_%H%M%S")
    main_path="evidencias_$current_time"
    mkdir -p "$main_path/redes" "$main_path/sistema" "$main_path/usuarios" "$main_path/logs"
    echo "$main_path"
}

# Función para obtener los comandos disponibles en Volatility 2
get_volatility2_commands() {
    commands=("imageinfo" "kdbgscan" "pslist" "pstree" "psscan" "dlllist" "ldrmodules" "filescan" "dumpfiles" "hivelist" "printkey" "hashdump" "netscan" "connections" "sockets" "getsids" "lsa_secrets" "cachedump" "memmap" "vadinfo" "vaddump" "malfind" "apihooks" "ssdt" "idt" "driverirp" "modscan" "devicetree" "cmdline" "handles")
    echo "${commands[@]}"
}

# Función para ejecutar los comandos de Volatility 2
run_volatility2_commands() {
    analysis_type=$1
    evidence_path=$2
    memory_dump_path=$3

    commands=$(get_volatility2_commands)
    
    for cmd in $commands; do
        if [[ "$cmd" == "netscan" || "$cmd" == "connections" || "$cmd" == "sockets" ]]; then
            output_file="$evidence_path/redes/${cmd}.txt"
        elif [[ "$cmd" == "pslist" || "$cmd" == "pstree" || "$cmd" == "psscan" || "$cmd" == "dlllist" || "$cmd" == "ldrmodules" ]]; then
            output_file="$evidence_path/sistema/${cmd}.txt"
        elif [[ "$cmd" == "lsa_secrets" || "$cmd" == "cachedump" || "$cmd" == "getsids" ]]; then
            output_file="$evidence_path/usuarios/${cmd}.txt"
        else
            output_file="$evidence_path/logs/${cmd}.txt"
        fi

        # Ejecutar el comando de Volatility 2 y guardar el resultado
        if [[ "$analysis_type" == "dump" ]]; then
            ./volatility/vol.py -f "$memory_dump_path" $cmd > "$output_file" 2>/dev/null
        else
            ./volatility/vol.py $cmd > "$output_file" 2>/dev/null
        fi
        
        # Verificar si el comando se ejecutó correctamente
        if [[ $? -eq 0 ]]; then
            echo "[*] Ejecutado: $cmd"
        else
            echo "[-] Error al ejecutar: $cmd"
        fi

        # Pausar entre comandos (3 segundos)
        sleep 3
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

# Ejecutar comandos de Volatility 2
run_volatility2_commands "$analysis_type" "$evidence_path" "$memory_dump_path"

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias.  ="
echo "============================================================================"
