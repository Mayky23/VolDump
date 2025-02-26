#!/bin/bash

# Colores para mejorar la interfaz
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

# Banner de la herramienta
echo -e "${BLUE}"
echo "============================================="
echo "          VOLDUMP - VOLATILITY 3             "
echo "               By: MARDH                     "
echo "============================================="
echo -e "${NC}"

# Variables globales
current_date=$(date +"%Y%m%d_%H%M%S")
evidence_dir="evidencias_$current_date"
log_file="$evidence_dir/logs/voldump.log"
pause_time=2 # Tiempo de espera entre comandos (en segundos)

# Crear estructura de carpetas
mkdir -p "$evidence_dir"/{memoria,sistema,logs}
touch "$log_file"

# Función para registrar logs
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$log_file"
}

# Función para verificar dependencias
verificar_dependencias() {
    log "Verificando dependencias..."
    if ! command -v python3 &> /dev/null || [[ $(python3 -c 'import sys; print(sys.version_info >= (3, 8))') == "False" ]]; then
        log "${RED}Python 3.8 o superior no está instalado. Instalando...${NC}"
        sudo apt-get update && sudo apt-get install -y python3 python3-pip || {
            log "${RED}Error: No se pudo instalar Python 3.${NC}"
            exit 1
        }
    else
        log "${GREEN}Python 3.8 o superior ya está instalado.${NC}"
    fi

    if ! command -v volatility &> /dev/null; then
        log "${YELLOW}Volatility 3 no está instalado. Instalando...${NC}"
        sudo pip3 install volatility3 || {
            log "${RED}Error: No se pudo instalar Volatility 3.${NC}"
            exit 1
        }
    else
        log "${GREEN}Volatility 3 ya está instalado.${NC}"
    fi
}

# Función para detectar el sistema operativo del volcado de memoria
detectar_sistema_operativo() {
    local memory_dump="$1"
    log "Detectando sistema operativo del volcado de memoria..."
    if volatility -f "$memory_dump" windows.info &> /dev/null; then
        echo "Windows"
    elif volatility -f "$memory_dump" linux.info &> /dev/null; then
        echo "Linux"
    else
        echo "Desconocido"
    fi
}

# Función para analizar un volcado de memoria
analizar_volcado_memoria() {
    read -p "Introduce la ruta completa del archivo de volcado de memoria: " memory_dump
    if [ ! -f "$memory_dump" ]; then
        log "${RED}El archivo no existe.${NC}"
        exit 1
    fi

    # Detectar el sistema operativo del volcado de memoria
    os_type=$(detectar_sistema_operativo "$memory_dump")
    log "Sistema operativo detectado: ${GREEN}$os_type${NC}"

    log "Analizando el volcado de memoria..."
    if [[ "$os_type" == "Windows" ]]; then
        plugins=(
            "windows.info"
            "windows.pslist"
            "windows.psscan"
            "windows.pstree"
            "windows.dlllist"
            "windows.handles"
            "windows.netscan"
            "windows.modules"
            "windows.svcscan"
            "windows.filescan"
            "windows.registry.printkey"
            "windows.malfind"
            "windows.cmdline"
        )
    elif [[ "$os_type" == "Linux" ]]; then
        plugins=(
            "linux.info"
            "linux.pslist"
            "linux.psscan"
            "linux.pstree"
            "linux.dlllist"
            "linux.handles"
            "linux.netscan"
            "linux.modules"
            "linux.filescan"
            "linux.bash"
            "linux.check_syscall"
        )
    else
        log "${RED}Sistema operativo no compatible.${NC}"
        exit 1
    fi

    # Ejecutar todos los plugins
    for plugin in "${plugins[@]}"; do
        log "Ejecutando plugin: ${YELLOW}$plugin${NC}"
        volatility -f "$memory_dump" "$plugin" > "$evidence_dir/memoria/${plugin//./_}.txt"
        sleep "$pause_time"
    done

    log "${GREEN}Análisis completado. Los resultados se han guardado en $evidence_dir/memoria.${NC}"
}

# Función para analizar el sistema operativo en ejecución
analizar_sistema_operativo() {
    log "Analizando el sistema operativo en ejecución..."
    os_type=$(uname -s)
    if [[ "$os_type" == "Linux" ]]; then
        log "Sistema operativo detectado: ${GREEN}Linux${NC}"
        plugins=(
            "linux.info"
            "linux.pslist"
            "linux.psscan"
            "linux.pstree"
            "linux.dlllist"
            "linux.handles"
            "linux.netscan"
            "linux.modules"
            "linux.filescan"
            "linux.bash"
            "linux.check_syscall"
        )

        # Ejecutar todos los plugins
        for plugin in "${plugins[@]}"; do
            log "Ejecutando plugin: ${YELLOW}$plugin${NC}"
            volatility -f /proc/kcore "$plugin" > "$evidence_dir/sistema/${plugin//./_}.txt"
            sleep "$pause_time"
        done
    elif [[ "$os_type" == "Windows" ]]; then
        log "Sistema operativo detectado: ${GREEN}Windows${NC}"
        log "${RED}No se puede analizar un sistema Windows en ejecución directamente. Use un volcado de memoria.${NC}"
        exit 1
    else
        log "${RED}Sistema operativo no compatible.${NC}"
        exit 1
    fi

    log "${GREEN}Análisis completado. Los resultados se han guardado en $evidence_dir/sistema.${NC}"
}

# Menú principal
menu_principal() {
    echo -e "${BLUE}Selecciona una opción:${NC}"
    echo "1. Analizar un volcado de memoria existente"
    echo "2. Analizar el sistema operativo en ejecución"
    echo "3. Salir"
    read -p "Opción: " option

    case $option in
        1)
            analizar_volcado_memoria
            ;;
        2)
            analizar_sistema_operativo
            ;;
        3)
            log "Saliendo de Voldump."
            exit 0
            ;;
        *)
            log "${RED}Opción no válida.${NC}"
            exit 1
            ;;
    esac
}

# Inicio del script
verificar_dependencias
menu_principal