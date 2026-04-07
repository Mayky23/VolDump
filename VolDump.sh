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
NC="\033[0m"

# Variables globales
APP_NAME="VolDump"
APP_VERSION="2.0.0"
CURRENT_DATE=$(date +"%Y%m%d_%H%M%S")
DEFAULT_EVIDENCE_DIR="evidencias_${CURRENT_DATE}"
EVIDENCE_DIR="${DEFAULT_EVIDENCE_DIR}"
LOG_DIR=""
LOG_FILE=""
SUMMARY_FILE=""
PAUSE_TIME=1
LIVE_MODE=false
SUDO=""
TOTAL_PLUGINS_RUN=0
SUCCESSFUL_PLUGINS=0
FAILED_PLUGINS=0
SUMMARY_WRITTEN=false
ANALYSIS_TARGET=""
TARGET_LABEL=""
TARGET_OS=""
REPORT_FILE=""

declare -a VOL_CMD=()
declare -a FAILED_PLUGIN_NAMES=()
declare -a SELECTED_PLUGIN_ENTRIES=()

readonly WINDOWS_PLUGINS=(
    "windows.info:general"
    "windows.pslist:procesos"
    "windows.psscan:procesos"
    "windows.pstree:procesos"
    "windows.cmdline:procesos"
    "windows.dlllist:modulos"
    "windows.handles:artefactos"
    "windows.netscan:red"
    "windows.modules:modulos"
    "windows.svcscan:persistencia"
    "windows.filescan:archivos"
    "windows.registry.printkey:registro"
    "windows.malfind:malware"
)

readonly LINUX_PLUGINS=(
    "linux.info:general"
    "linux.pslist:procesos"
    "linux.psscan:procesos"
    "linux.pstree:procesos"
    "linux.psaux:procesos"
    "linux.bash:artefactos"
    "linux.lsof:archivos"
    "linux.lsmod:modulos"
    "linux.netfilter:red"
    "linux.mountinfo:sistema"
    "linux.kmsg:sistema"
    "linux.check_syscall:malware"
)

print_banner() {
    echo -e "${BLUE}"
    echo "============================================="
    echo "          VOLDUMP - VOLATILITY 3             "
    echo "                 By: Mayky                   "
    echo "============================================="
    echo -e "${NC}"
}

usage() {
    cat <<EOF
Uso: ./VolDump.sh

VolDump funciona en modo interactivo:
  1. Pregunta si quieres analizar un volcado o memoria en vivo.
  2. Detecta el sistema operativo cuando aplica.
  3. Te deja elegir qué áreas quieres extraer.
  4. Ejecuta los plugins seleccionados.
  5. Genera evidencias, log, resumen y reporte final.
EOF
}

log() {
    local mensaje="$1"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - ${mensaje}" | tee -a "${LOG_FILE}"
}

die() {
    log "${RED}[!] $1${NC}"
    exit 1
}

sanitize_filename() {
    local value="$1"
    value="${value//./_}"
    value="${value//\//_}"
    echo "${value}"
}

prepare_workspace() {
    LOG_DIR="${EVIDENCE_DIR}/logs"
    SUMMARY_FILE="${EVIDENCE_DIR}/resumen.txt"
    REPORT_FILE="${EVIDENCE_DIR}/reporte.md"
    LOG_FILE="${LOG_DIR}/voldump.log"

    mkdir -p \
        "${EVIDENCE_DIR}/memoria" \
        "${EVIDENCE_DIR}/sistema" \
        "${LOG_DIR}"
    touch "${LOG_FILE}" "${SUMMARY_FILE}" "${REPORT_FILE}"
}

check_runtime() {
    local host_os
    host_os=$(uname -s)

    if [[ "${host_os}" != "Linux" ]]; then
        echo -e "${RED}[!] Este script está diseñado para ejecutarse en Linux.${NC}" >&2
        echo "Sistema detectado: ${host_os}" >&2
        exit 1
    fi

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            echo -e "${RED}[!] Este script requiere permisos de administrador (root o sudo).${NC}" >&2
            exit 1
        fi
    fi
}

run_privileged() {
    if [[ -n "${SUDO}" ]]; then
        "${SUDO}" "$@"
    else
        "$@"
    fi
}

parse_arguments() {
    if [[ $# -eq 0 ]]; then
        return
    fi

    case "$*" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 0
            ;;
    esac
}

write_summary() {
    {
        echo "VolDump ${APP_VERSION}"
        echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Directorio de evidencias: ${EVIDENCE_DIR}"
        echo "Objetivo analizado: ${TARGET_LABEL:-No definido}"
        echo "Sistema operativo objetivo: ${TARGET_OS:-No definido}"
        echo "Plugins ejecutados: ${TOTAL_PLUGINS_RUN}"
        echo "Plugins correctos: ${SUCCESSFUL_PLUGINS}"
        echo "Plugins con errores: ${FAILED_PLUGINS}"
        if [[ ${#SELECTED_PLUGIN_ENTRIES[@]} -gt 0 ]]; then
            echo "Selección realizada:"
            printf ' - %s\n' "${SELECTED_PLUGIN_ENTRIES[@]}"
        fi
        if [[ ${#FAILED_PLUGIN_NAMES[@]} -gt 0 ]]; then
            echo "Listado de plugins con errores:"
            printf ' - %s\n' "${FAILED_PLUGIN_NAMES[@]}"
        fi
        echo "Log: ${LOG_FILE}"
        echo "Reporte: ${REPORT_FILE}"
    } >"${SUMMARY_FILE}"
}

finish_run() {
    if [[ -z "${LOG_FILE}" || -z "${SUMMARY_FILE}" || "${SUMMARY_WRITTEN}" == true ]]; then
        return
    fi

    write_summary
    SUMMARY_WRITTEN=true
    log "[*] Resumen guardado en: ${SUMMARY_FILE}"
}

trap 'log "${RED}[*] Ejecución interrumpida por el usuario.${NC}"; finish_run; exit 1' INT TERM
trap 'finish_run' EXIT

# ---------------- DEPENDENCIAS ---------------- #

verificar_python() {
    log "[*] Verificando Python 3..."

    if ! command -v python3 >/dev/null 2>&1; then
        instalar_python3
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        die "No se pudo instalar Python 3 automáticamente."
    fi

    local py_major py_minor py_version
    py_major=$(python3 - <<'EOF'
import sys
print(sys.version_info[0])
EOF
)
    py_minor=$(python3 - <<'EOF'
import sys
print(sys.version_info[1])
EOF
)
    py_version=$(python3 - <<'EOF'
import sys
print(".".join(map(str, sys.version_info[:3])))
EOF
)

    if (( py_major < 3 || (py_major == 3 && py_minor < 8) )); then
        die "Se requiere Python 3.8 o superior. Versión detectada: ${py_version}."
    fi

    log "${GREEN}[OK] Python 3 detectado correctamente (versión ${py_version}).${NC}"

    if ! python3 -m pip --version >/dev/null 2>&1; then
        instalar_pip3
    fi

    if ! python3 -m pip --version >/dev/null 2>&1; then
        die "No se pudo dejar pip operativo para Python 3."
    fi
}

verificar_volatility3() {
    log "[*] Verificando Volatility 3..."

    if command -v vol >/dev/null 2>&1; then
        VOL_CMD=(vol)
        log "${GREEN}[OK] Volatility 3 ya está instalado (comando 'vol').${NC}"
        return
    fi

    if python3 - <<'EOF' >/dev/null 2>&1
import volatility3  # noqa: F401
EOF
    then
        VOL_CMD=(python3 -m volatility3)
        log "${YELLOW}[OK] Volatility 3 está instalado como módulo de Python. Se usará 'python3 -m volatility3'.${NC}"
        return
    fi

    log "${YELLOW}[!] Volatility 3 no está instalado. Intentando instalarlo con pip (volatility3[full])...${NC}"
    if instalar_volatility3; then
        log "${GREEN}[OK] Volatility 3 instalado correctamente.${NC}"
    else
        die "Error al instalar Volatility 3. Revisa la salida anterior e inténtalo de nuevo."
    fi

    if command -v vol >/dev/null 2>&1; then
        VOL_CMD=(vol)
    elif python3 - <<'EOF' >/dev/null 2>&1
import volatility3  # noqa: F401
EOF
    then
        VOL_CMD=(python3 -m volatility3)
    else
        die "No se pudo localizar Volatility 3 tras la instalación."
    fi
}

verificar_dependencias() {
    verificar_python
    verificar_volatility3
}

instalar_python3() {
    log "${YELLOW}[!] Python 3 no está instalado. Intentando instalarlo automáticamente...${NC}"

    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update
        run_privileged apt-get install -y python3 python3-pip
        return 0
    fi

    if command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y python3 python3-pip
        return 0
    fi

    if command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y python3 python3-pip
        return 0
    fi

    if command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -Sy --noconfirm python python-pip
        return 0
    fi

    if command -v zypper >/dev/null 2>&1; then
        run_privileged zypper --non-interactive install python3 python3-pip
        return 0
    fi

    if command -v apk >/dev/null 2>&1; then
        run_privileged apk add --no-cache python3 py3-pip
        return 0
    fi

    if command -v microdnf >/dev/null 2>&1; then
        run_privileged microdnf install -y python3 python3-pip
        return 0
    fi

    return 1
}

instalar_pip3() {
    log "${YELLOW}[!] 'pip' para Python 3 no está instalado. Intentando instalarlo automáticamente...${NC}"

    if command -v apt-get >/dev/null 2>&1; then
        run_privileged apt-get update
        run_privileged apt-get install -y python3-pip
        return 0
    fi

    if command -v dnf >/dev/null 2>&1; then
        run_privileged dnf install -y python3-pip
        return 0
    fi

    if command -v yum >/dev/null 2>&1; then
        run_privileged yum install -y python3-pip
        return 0
    fi

    if command -v pacman >/dev/null 2>&1; then
        run_privileged pacman -Sy --noconfirm python-pip
        return 0
    fi

    if command -v zypper >/dev/null 2>&1; then
        run_privileged zypper --non-interactive install python3-pip
        return 0
    fi

    if command -v apk >/dev/null 2>&1; then
        run_privileged apk add --no-cache py3-pip
        return 0
    fi

    if command -v microdnf >/dev/null 2>&1; then
        run_privileged microdnf install -y python3-pip
        return 0
    fi

    log "${YELLOW}[!] No hay gestor compatible para instalar pip. Intentando con ensurepip...${NC}"
    if python3 -m ensurepip --upgrade >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

instalar_volatility3() {
    if python3 -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1; then
        :
    fi

    if python3 -m pip install 'volatility3[full]'; then
        return 0
    fi

    log "${YELLOW}[!] La instalación con extras falló. Intentando instalar el paquete base de Volatility 3...${NC}"
    if python3 -m pip install volatility3; then
        return 0
    fi

    return 1
}

# --------------- FUNCIONES COMUNES --------------- #

validar_volcado() {
    local memory_dump="$1"

    [[ -f "${memory_dump}" ]] || die "El archivo '${memory_dump}' no existe o no es un archivo regular."
    [[ -r "${memory_dump}" ]] || die "No se tienen permisos de lectura sobre '${memory_dump}'."
}

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

plugin_output_dir() {
    local analysis_scope="$1"
    local category="$2"
    local target_dir="${EVIDENCE_DIR}/${analysis_scope}/${category}"

    mkdir -p "${target_dir}"
    echo "${target_dir}"
}

registrar_resultado_plugin() {
    local plugin="$1"
    local success="$2"

    TOTAL_PLUGINS_RUN=$((TOTAL_PLUGINS_RUN + 1))

    if [[ "${success}" == "true" ]]; then
        SUCCESSFUL_PLUGINS=$((SUCCESSFUL_PLUGINS + 1))
    else
        FAILED_PLUGINS=$((FAILED_PLUGINS + 1))
        FAILED_PLUGIN_NAMES+=("${plugin}")
    fi
}

ejecutar_plugin() {
    local fuente="$1"
    local plugin="$2"
    local analysis_scope="$3"
    local category="$4"

    local target_dir out_file err_file sanitized_name
    target_dir=$(plugin_output_dir "${analysis_scope}" "${category}")
    sanitized_name=$(sanitize_filename "${plugin}")
    out_file="${target_dir}/${sanitized_name}.txt"
    err_file="${LOG_DIR}/${sanitized_name}_error.txt"

    log "[*] Ejecutando plugin: ${YELLOW}${plugin}${NC}"
    if "${VOL_CMD[@]}" -f "${fuente}" "${plugin}" >"${out_file}" 2>"${err_file}"; then
        registrar_resultado_plugin "${plugin}" "true"
        if [[ ! -s "${err_file}" ]]; then
            rm -f "${err_file}"
        fi
    else
        registrar_resultado_plugin "${plugin}" "false"
        log "${YELLOW}[!] El plugin ${plugin} terminó con errores. Revisa: ${err_file}.${NC}"
    fi

    sleep "${PAUSE_TIME}"
}

ejecutar_plugins_desde_lista() {
    local fuente="$1"
    local analysis_scope="$2"
    shift 2

    local plugin_entry plugin category
    for plugin_entry in "$@"; do
        plugin="${plugin_entry%%:*}"
        category="${plugin_entry##*:}"
        ejecutar_plugin "${fuente}" "${plugin}" "${analysis_scope}" "${category}"
    done
}

obtener_categorias_disponibles() {
    local os_type="$1"

    case "${os_type}" in
        Windows)
            cat <<'EOF'
1|Informacion general|general
2|Procesos y arbol de procesos|procesos
3|Modulos y DLLs|modulos
4|Red y conexiones|red
5|Archivos y handles|archivos
6|Registro y persistencia|registro,persistencia
7|Malware y anomalías|malware
8|Todo|ALL
EOF
            ;;
        Linux)
            cat <<'EOF'
1|Informacion general|general
2|Procesos y actividad de usuario|procesos,artefactos
3|Modulos y kernel|modulos,sistema
4|Red y filtrado|red
5|Archivos abiertos y montajes|archivos,sistema
6|Indicadores de malware|malware
7|Todo|ALL
EOF
            ;;
        *)
            return 1
            ;;
    esac
}

categoria_seleccionada() {
    local selected_csv="$1"
    local desired="$2"
    local item

    IFS=',' read -r -a __selected_items <<< "${selected_csv}"
    for item in "${__selected_items[@]}"; do
        if [[ "${item}" == "${desired}" ]]; then
            return 0
        fi
    done

    return 1
}

seleccionar_plugins_interactivamente() {
    local os_type="$1"
    local plugin_entry plugin category selected_options
    local category_catalog line option_id option_label option_values
    local -a available_plugins=()

    SELECTED_PLUGIN_ENTRIES=()

    if [[ "${os_type}" == "Windows" ]]; then
        available_plugins=("${WINDOWS_PLUGINS[@]}")
    else
        available_plugins=("${LINUX_PLUGINS[@]}")
    fi

    echo
    echo -e "${BLUE}Selecciona qué quieres extraer:${NC}"
    category_catalog=$(obtener_categorias_disponibles "${os_type}")
    while IFS= read -r line; do
        option_id="${line%%|*}"
        line="${line#*|}"
        option_label="${line%%|*}"
        option_values="${line##*|}"
        echo "${option_id}. ${option_label}"
    done <<< "${category_catalog}"

    echo
    read -r -p "Escribe una o varias opciones separadas por comas: " selected_options
    selected_options="${selected_options// /}"
    [[ -n "${selected_options}" ]] || die "Debes seleccionar al menos una opción."

    while IFS= read -r line; do
        option_id="${line%%|*}"
        line="${line#*|}"
        option_label="${line%%|*}"
        option_values="${line##*|}"

        if categoria_seleccionada "${selected_options}" "${option_id}"; then
            if [[ "${option_values}" == "ALL" ]]; then
                SELECTED_PLUGIN_ENTRIES=("${available_plugins[@]}")
                return
            fi

            for plugin_entry in "${available_plugins[@]}"; do
                plugin="${plugin_entry%%:*}"
                category="${plugin_entry##*:}"
                IFS=',' read -r -a __option_categories <<< "${option_values}"
                local match_found=false
                local requested_category
                for requested_category in "${__option_categories[@]}"; do
                    if [[ "${category}" == "${requested_category}" ]]; then
                        match_found=true
                        break
                    fi
                done

                if [[ "${match_found}" == true ]]; then
                    local already_added=false
                    local existing_entry
                    for existing_entry in "${SELECTED_PLUGIN_ENTRIES[@]}"; do
                        if [[ "${existing_entry}" == "${plugin_entry}" ]]; then
                            already_added=true
                            break
                        fi
                    done

                    if [[ "${already_added}" == false ]]; then
                        SELECTED_PLUGIN_ENTRIES+=("${plugin_entry}")
                    fi
                fi
            done
        fi
    done <<< "${category_catalog}"

    [[ ${#SELECTED_PLUGIN_ENTRIES[@]} -gt 0 ]] || die "La selección no contiene categorías válidas."
}

generar_reporte() {
    {
        echo "# Reporte VolDump"
        echo
        echo "- Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "- Objetivo: ${TARGET_LABEL}"
        echo "- Sistema operativo detectado: ${TARGET_OS}"
        echo "- Directorio de evidencias: ${EVIDENCE_DIR}"
        echo "- Plugins ejecutados: ${TOTAL_PLUGINS_RUN}"
        echo "- Plugins correctos: ${SUCCESSFUL_PLUGINS}"
        echo "- Plugins con errores: ${FAILED_PLUGINS}"
        echo
        echo "## Extracción solicitada"
        printf -- "- %s\n" "${SELECTED_PLUGIN_ENTRIES[@]}"
        echo
        echo "## Resultado"
        if [[ ${FAILED_PLUGINS} -eq 0 ]]; then
            echo "La ejecución terminó sin errores registrados por los plugins seleccionados."
        else
            echo "La ejecución terminó con errores parciales. Conviene revisar los ficheros de error en \`${LOG_DIR}\`."
            printf -- "- %s\n" "${FAILED_PLUGIN_NAMES[@]}"
        fi
        echo
        echo "## Artefactos generados"
        echo "- Log: ${LOG_FILE}"
        echo "- Resumen: ${SUMMARY_FILE}"
        if [[ "${LIVE_MODE}" == true ]]; then
            echo "- Resultados del análisis en vivo: ${EVIDENCE_DIR}/sistema"
        else
            echo "- Resultados del volcado: ${EVIDENCE_DIR}/memoria"
        fi
    } > "${REPORT_FILE}"
}

# --------------- ANÁLISIS DE VOLCADO --------------- #

analizar_volcado_memoria() {
    local memory_dump os_type
    read -r -p "Introduce la ruta completa del archivo de volcado de memoria: " memory_dump

    validar_volcado "${memory_dump}"

    ANALYSIS_TARGET="${memory_dump}"
    TARGET_LABEL="Volcado: ${memory_dump}"
    os_type=$(detectar_sistema_operativo "${memory_dump}")
    TARGET_OS="${os_type}"
    log "[*] Sistema operativo detectado: ${GREEN}${os_type}${NC}"

    if [[ "${os_type}" == "Desconocido" ]]; then
        die "No se pudo determinar el sistema operativo del volcado."
    fi

    seleccionar_plugins_interactivamente "${os_type}"
    log "[*] Iniciando análisis del volcado de memoria (${os_type})..."
    ejecutar_plugins_desde_lista "${memory_dump}" "memoria" "${SELECTED_PLUGIN_ENTRIES[@]}"
    generar_reporte
    log "${GREEN}[OK] Análisis del volcado completado. Resultados en: ${EVIDENCE_DIR}/memoria${NC}"
}

# --------------- ANÁLISIS DE MEMORIA EN VIVO --------------- #

analizar_sistema_en_ejecucion() {
    log "[*] Analizando la memoria del sistema en ejecución..."

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "El análisis de memoria en vivo requiere ejecutar el script como root (para acceder a /proc/kcore)."
    fi

    if [[ ! -r /proc/kcore ]]; then
        die "No se puede leer /proc/kcore. Comprueba permisos o configuración del kernel."
    fi

    LIVE_MODE=true
    ANALYSIS_TARGET="/proc/kcore"
    TARGET_LABEL="Memoria en vivo del sistema local"
    TARGET_OS="Linux"
    seleccionar_plugins_interactivamente "Linux"
    log "${YELLOW}[!] El análisis sobre /proc/kcore depende de los símbolos y de la configuración del kernel; algunos plugins pueden fallar aunque Volatility esté instalado correctamente.${NC}"
    ejecutar_plugins_desde_lista "/proc/kcore" "sistema" "${SELECTED_PLUGIN_ENTRIES[@]}"
    generar_reporte
    log "${GREEN}[OK] Análisis del sistema en ejecución completado. Resultados en: ${EVIDENCE_DIR}/sistema${NC}"
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
                log "[*] Saliendo de ${APP_NAME}. Archivo de log: ${LOG_FILE}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Opción no válida. Inténtalo de nuevo.${NC}"
                ;;
        esac
    done
}

# --------------- INICIO --------------- #

parse_arguments "$@"
check_runtime
prepare_workspace
print_banner
log "[*] Iniciando ${APP_NAME} ${APP_VERSION}."
verificar_dependencias
echo
echo -e "${GREEN}[OK] Dependencias comprobadas. Volatility 3 está listo para usarse.${NC}"
menu_principal
