#!/bin/bash

# -------------------------------------------------------------------
# Función para verificar si un comando está instalado
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
    sudo apt-get install -y git python2 python3 python3-pip libdistorm3-dev libssl-dev libffi-dev python-yara python-crypto >/dev/null 2>&1
    pip3 install distorm3 yara-python pycrypto >/dev/null 2>&1
}

# -------------------------------------------------------------------
# Función para instalar dependencias en Windows (solo mensaje)
# -------------------------------------------------------------------
install_dependencies_windows() {
    echo "[!] Por favor, instale Python 2 y 3 manualmente desde https://www.python.org/downloads/."
    exit 1
}

# -------------------------------------------------------------------
# Función para descargar/instalar Volatility 2 y 3
# -------------------------------------------------------------------
install_volatility() {
    if [[ ! -d "volatility" ]]; then
        echo "[*] Descargando Volatility 2..."
        git clone https://github.com/volatilityfoundation/volatility.git >/dev/null 2>&1 \
            && echo "[*] Descarga de Volatility 2 completada."
    fi
    if [[ ! -d "volatility3" ]]; then
        echo "[*] Descargando Volatility 3..."
        git clone https://github.com/volatilityfoundation/volatility3.git >/dev/null 2>&1 \
            && echo "[*] Descarga de Volatility 3 completada."
    fi
}

# -------------------------------------------------------------------
# Función para mostrar el banner
# -------------------------------------------------------------------
display_banner() {
    echo "=========================================="
    echo "= VOLDUM - Volatility 2 and Volatility 3 ="
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
            2) echo "2"; return ;;  # Retorna "2" para Volatility 2
            3) echo "3"; return ;;  # Retorna "3" para Volatility 3
            *) echo "[-] Opción no válida, intente de nuevo." ;;
        esac
    done
}

# -------------------------------------------------------------------
# Función para elegir el tipo de análisis
# -------------------------------------------------------------------
choose_analysis_type() {
    while true; do
        read -p "[+] Seleccione el tipo de análisis (1) Volcado de memoria existente (2) Análisis en vivo del sistema actual (1/2): " choice
        case $choice in
            1) echo "dump"; return ;;  # Retorna "dump" para análisis de volcado de memoria
            2) echo "live"; return ;;  # Retorna "live" para análisis en vivo
            *) echo "[-] Opción no válida, intente de nuevo." ;;
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
    local date_time=$(date +"%Y%m%d_%H%M%S")
    local evidence_folder="$base_path/Evidencias_$date_time"
    
    mkdir -p "$evidence_folder/Red"
    mkdir -p "$evidence_folder/Sistema"
    mkdir -p "$evidence_folder/Logs"
    mkdir -p "$evidence_folder/Proceso"

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

    # Comandos Volatility 3 (notar que muchos requieren prefijo 'windows.' o 'linux.'; se ajusta según tu SO)
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

    # Mapeo (asociamos cada comando con la carpeta donde guardaremos la evidencia)
    # -------------------------------------------------------------------
    # Puedes ajustar esto a conveniencia:
    #   - Red       -> netscan, connections
    #   - Proceso   -> pslist, pstree, psscan, handles, etc.
    #   - Sistema   -> lsa_secrets, cachedump, hashdump, apihooks, ssdt, idt, etc.
    #   - Logs      -> filescan, dumpfiles, malfind, memmap, vadinfo, etc.
    # -------------------------------------------------------------------
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

    # Para Volatility 3, debido a que los comandos tienen prefijo "linux."
    # (o "windows."), creamos un mapeo similar pero con esas claves.
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

    # Definir el ejecutable de Volatility y lista de comandos
    local vol_cmd
    local commands_to_run=()

    if [[ "$volatility_version" == "2" ]]; then
        vol_cmd="./volatility/vol.py"
        commands_to_run=("${commands_vol2[@]}")
    else
        vol_cmd="./volatility3/vol.py"
        commands_to_run=("${commands_vol3[@]}")
    fi

    # Ejecutar cada comando y guardar en la carpeta correspondiente
    for cmd in "${commands_to_run[@]}"; do

        # Determinar carpeta destino según el mapeo
        local folder="Otros"
        if [[ "$volatility_version" == "2" ]]; then
            folder="${folder_map_vol2[$cmd]}"
        else
            folder="${folder_map_vol3[$cmd]}"
        fi
        if [[ -z "$folder" ]]; then
            folder="Otros"
        fi

        # Construir ruta de salida
        local output_file="$evidence_path/$folder/${cmd}.txt"

        # Ejecutar Volatility (con volcado o en vivo)
        if [[ "$analysis_type" == "dump" ]]; then
            $vol_cmd -f "$memory_dump_path" $cmd > "$output_file" 2>/dev/null
        else
            $vol_cmd $cmd > "$output_file" 2>/dev/null
        fi

        echo "[*] Ejecutado: $cmd -> Guardado en '$folder/${cmd}.txt'"
        sleep 1  # Pausa de 1 segundo entre comandos (opcional)
    done
}

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
display_banner

# Verificar e instalar Python 2 y 3 si no están instalados
if ! is_installed "python2" || ! is_installed "python3"; then
    echo "[-] Python 2 o Python 3 no están instalados."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        install_dependencies_linux
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        install_dependencies_windows
    else
        echo "[-] Sistema operativo no compatible."
        exit 1
    fi
fi

# Verificar e instalar Volatility si falta
install_volatility

# Elegir versión de Volatility
volatility_version=$(choose_volatility_version)

# Elegir tipo de análisis
analysis_type=$(choose_analysis_type)

# Obtener ruta donde se guardarán las evidencias
evidence_base_path=$(get_evidence_path)

# Crear carpeta de evidencias con subcarpetas
evidence_folder=$(create_evidence_folder "$evidence_base_path")

# Si se eligió volcado de memoria, pedir la ruta
memory_dump_path=""
if [[ "$analysis_type" == "dump" ]]; then
    read -p "[+] Ingrese la ruta del volcado de memoria (archivo .raw, .mem, etc.): " memory_dump_path
    if [[ ! -f "$memory_dump_path" ]]; then
        echo "[-] Archivo no encontrado, verifica la ruta y vuelve a intentarlo."
        exit 1
    fi
fi

# Ejecutar comandos de Volatility y almacenar resultados
run_volatility_commands "$volatility_version" "$analysis_type" "$evidence_folder" "$memory_dump_path"

echo "============================================================================"
echo "=  Análisis completado. Resultados guardados en la carpeta de evidencias:  ="
echo "=  $evidence_folder"
echo "============================================================================"
