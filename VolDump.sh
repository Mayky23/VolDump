#!/usr/bin/env bash

# VOLDUMP - Frontend sencillo para Volatility 3
# Requisitos:
#   - Linux (preferiblemente Debian/Ubuntu)
#   - apt-get para instalación automática
#   - Permisos de sudo/root para instalar paquetes y analizar memoria en vivo

set -o errexit
set -o pipefail
set -o nounset

# Colores
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m" # Sin color

# Comprobar sistema operativo
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${RED}[!] Este script está diseñado para ejecutarse en Linux.${NC}" >&2
    echo "Sistema detectado: $(uname -s)" >&2
    exit 1
fi

# Detectar si tenemos sudo o ya somos root
SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Este script requiere permisos de administrador (root o sudo).${NC}" >&2
        exit 1
    fi
fi

# Banner
echo -e "${BLUE}"
echo "============================================="
echo "          VOLDUMP - VOLATILITY 3             "
echo "                 By: MARDH                   "
echo "============================================="
echo -e "${NC}"

# Variables globales
current_date=$(date +"%Y%m%d_%H%M%S")
evidence_dir="evidencias_${current_date}"
log_dir="${evidence_dir}/logs"
log_file="${log_dir}/voldump.log"
pause_time=2 # segundos entre plugins

# Crear estructura de carpetas
mkdir -p "${evidence_dir}/memoria" "${evidence_dir}/sistema" "${log_dir}"
touch "${log_file}"

# Comando de Volatility (se rellenará en verificar_volatility3)
declare -a VOL_CMD=()

# Función de log
log() {
    local mensaje="$1"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${mensaje}" | tee -a "${log_file}"
}

# Traps para salir de forma controlada
trap 'log "${RED}[*] Ejecución interrumpida por el usuario.${NC}"; exit 1' INT TERM

# ---------------- DEPENDENCIAS ---------------- #

verificar_python() {
    log "[*] Verificando Python 3..."

    if ! command -v python3 >/dev/null 2>&1; then
        log "${YELLOW}[!] Python 3 no está instalado. Intentando instalarlo (requiere apt-get)...${NC}"
        if command -v apt-get >/dev/null 2>&1; then
            ${SUDO} apt-get update
            ${SUDO} apt-get install -y python3 python3-pip
        else
            log "${RED}[!] No se encontró 'apt-get'. Instala Python 3.8+ y pip manualmente e inténtalo de nuevo.${NC}"
            exit 1
        fi
    fi

    local py_major py_minor py_version
    py_major=$(python3 - << 'EOF'
import sys
print(sys.version_info[0])
EOF
)
    py_minor=$(python3 - << 'EOF'
import sys
print(sys.version_info[1])
EOF
)
    py_version=$(python3 - << 'EOF'
import sys
print(".".join(map(str, sys.version_info[:3])))
EOF
)

    if (( py_major < 3 || (py_major == 3 && py_minor < 8) )); then
        log "${RED}[!] Se requiere Python 3.8 o superior. Versión detectada: ${py_version}.${NC}"
        exit 1
    else
        log "${GREEN}[OK] Python 3 detectado correctamente (versión ${py_version}).${NC}"
    fi

    # Verificar pip
    if ! python3 -m pip --version >/dev/null 2>&1; then
        log "${YELLOW}[!] 'pip' para Python 3 no está instalado. Intentando instalarlo...${NC}"
        if command -v apt-get >/dev/null 2>&1; then
            ${SUDO} apt-get update
            ${SUDO} apt-get install -y python3-pip
        else
            log "${RED}[!] No se encontró 'apt-get'. Instala 'python3-pip' manualmente e inténtalo de nuevo.${NC}"
            exit 1
        fi
    fi
}

verificar_volatility3() {
    log "[*] Verificando Volatility 3..."

    # ¿Existe el comando vol (CLI oficial de Volatility 3)?
    if command -v vol >/dev/null 2>&1; then
        VOL_CMD=(vol)
        log "${GREEN}[OK] Volatility 3 ya está instalado (comando 'vol').${NC}"
        return
    fi

    # ¿Existe el módulo de Python volatility3?
    if python3 - << 'EOF' >/dev/null 2>&1
import volatility3  # noqa: F401
EOF
    then
        VOL_CMD=(python3 -m volatility3)
        log "${YELLOW}[OK] Volatility 3 está instalado como módulo de Python. Se usará 'python3 -m volatility3'.${NC}"
        return
    fi

    # Instalar Volatility 3
    log "${YELLOW}[!] Volatility 3 no está instalado. Intentando instalarlo con pip (volatility3[full])...${NC}"
    if ${SUDO} python3 -m pip install 'volatility3[full]'; then
        log "${GREEN}[OK] Volatility 3 instalado correctamente.${NC}"
    else
        log "${RED}[!] Error al instalar Volatility 3. Revisa la salida anterior e inténtalo de nuevo.${NC}"
        exit 1
    fi

    # Volver a comprobar
    if command -v vol >/dev/null 2>&1; then
        VOL_CMD=(vol)
    elif python3 - << 'EOF' >/dev/null 2>&1
import volatility3  # noqa: F401
EOF
    then
        VOL_CMD=(python3 -m volatility3)
    else
        log "${RED}[!] No se pudo localizar Volatility 3 tras la instalación.${NC}"
        exit 1
    fi
}

verificar_dependencias() {
    verificar_python
    verificar_volatility3
}

# --------------- FUNCIONES COMUNES --------------- #

detectar_sistema_operativo() {
    local memory_dump="$1"
    log "[*] Detectando sistema operativo del volcado de memoria..."

    if "${VOL_CMD[@]}" -f "${memory_dump}" windows.info >/dev/null 2>&1; then
        echo "Windows"
        return
    fi

    if "${VOL_CMD[@]}" -f "${memory_dump}" linux.info >/dev/null 2>&1; then
        echo "Linux"
        return
    fi

    echo "Desconocido"
}

ejecutar_plugin() {
    local fuente="$1"
    local plugin="$2"
    local subdir="$3"

    local out_file err_file
    out_file="${evidence_dir}/${subdir}/${plugin//./_}.txt"
    err_file="${log_dir}/${plugin//./_}_error.txt"

    log "[*] Ejecutando plugin: ${YELLOW}${plugin}${NC}"
    if ! "${VOL_CMD[@]}" -f "${fuente}" "${plugin}" >"${out_file}" 2>"${err_file}"; then
        log "${YELLOW}[!] El plugin ${plugin} terminó con errores. Revisa: ${err_file}.${NC}"
    else
        # Si el fichero de error está vacío, lo eliminamos
        if [[ ! -s "${err_file}" ]]; then
            rm -f "${err_file}"
        fi
    fi

    sleep "${pause_time}"
}

# --------------- ANÁLISIS DE VOLCADO --------------- #

analizar_volcado_memoria() {
    local memory_dump os_type
    read -r -p "Introduce la ruta completa del archivo de volcado de memoria: " memory_dump

    if [[ ! -f "${memory_dump}" ]]; then
        log "${RED}[!] El archivo '${memory_dump}' no existe o no es un archivo regular.${NC}"
        exit 1
    fi

    if [[ ! -r "${memory_dump}" ]]; then
        log "${RED}[!] No se tienen permisos de lectura sobre '${memory_dump}'.${NC}"
        exit 1
    fi

    os_type=$(detectar_sistema_operativo "${memory_dump}")
    log "[*] Sistema operativo detectado: ${GREEN}${os_type}${NC}"

    if [[ "${os_type}" == "Desconocido" ]]; then
        log "${RED}[!] No se pudo determinar el sistema operativo del volcado. Abortando análisis.${NC}"
        exit 1
    fi

    log "[*] Iniciando análisis del volcado de memoria (${os_type})..."
    local -a plugins=()

    if [[ "${os_type}" == "Windows" ]]; then
        plugins=(
            "windows.info"
            "windows.pslist"
            "windows.psscan"
            "windows.pstree"
            "windows.cmdline"
            "windows.dlllist"
            "windows.handles"
            "windows.netscan"
            "windows.modules"
            "windows.svcscan"
            "windows.filescan"
            "windows.registry.printkey"
            "windows.malfind"
        )
    elif [[ "${os_type}" == "Linux" ]]; then
        plugins=(
            "linux.info"
            "linux.pslist"
            "linux.psscan"
            "linux.pstree"
            "linux.psaux"
            "linux.bash"
            "linux.lsof"
            "linux.lsmod"
            "linux.netfilter"
            "linux.mountinfo"
            "linux.kmsg"
            "linux.check_syscall"
        )
    else
        log "${RED}[!] Sistema operativo '${os_type}' no soportado actualmente.${NC}"
        exit 1
    fi

    for plugin in "${plugins[@]}"; do
        ejecutar_plugin "${memory_dump}" "${plugin}" "memoria"
    done

    log "${GREEN}[OK] Análisis del volcado completado. Resultados en: ${evidence_dir}/memoria${NC}"
}

# --------------- ANÁLISIS DE MEMORIA EN VIVO --------------- #

analizar_sistema_en_ejecucion() {
    log "[*] Analizando la memoria del sistema en ejecución..."

    local host_os
    host_os=$(uname -s)

    if [[ "${host_os}" != "Linux" ]]; then
        log "${RED}[!] El análisis de memoria en vivo sólo está soportado en Linux.${NC}"
        exit 1
    fi

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log "${RED}[!] El análisis de memoria en vivo requiere ejecutar el script como root (para acceder a /proc/kcore).${NC}"
        exit 1
    fi

    if [[ ! -r /proc/kcore ]]; then
        log "${RED}[!] No se puede leer /proc/kcore. Comprueba permisos o configuración del kernel.${NC}"
        exit 1
    fi

    local -a plugins=(
        "linux.info"
        "linux.pslist"
        "linux.psscan"
        "linux.pstree"
        "linux.psaux"
        "linux.bash"
        "linux.lsof"
        "linux.lsmod"
        "linux.netfilter"
        "linux.mountinfo"
        "linux.kmsg"
        "linux.check_syscall"
    )

    for plugin in "${plugins[@]}"; do
        ejecutar_plugin "/proc/kcore" "${plugin}" "sistema"
    done

    log "${GREEN}[OK] Análisis del sistema en ejecución completado. Resultados en: ${evidence_dir}/sistema${NC}"
}

# --------------- MENÚ PRINCIPAL --------------- #

menu_principal() {
    while true; do
        echo
        echo -e "${BLUE}¿Qué deseas hacer ahora?${NC}"
        echo "1. Analizar un volcado de memoria existente"
        echo "2. Analizar la memoria de este equipo (Linux en ejecución)"
        echo "3. Salir"
        read -r -p "Opción: " opcion

        case "${opcion}" in
            1)
                analizar_volcado_memoria
                break
                ;;
            2)
                analizar_sistema_en_ejecucion
                break
                ;;
            3)
                log "[*] Saliendo de VOLDUMP. Archivo de log: ${log_file}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Opción no válida. Inténtalo de nuevo.${NC}"
                ;;
        esac
    done
}

# --------------- INICIO --------------- #

verificar_dependencias
echo
echo -e "${GREEN}[OK] Dependencias comprobadas. Volatility 3 está listo para usarse.${NC}"
menu_principal
