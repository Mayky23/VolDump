#!/usr/bin/env bash
#
# VolDump - Frontend para análisis forense de memoria con Volatility 3 y Volatility 2.
# Autor: Mayky
#
# Ejecuta "./VolDump.sh --help" para ver todas las opciones.

if [ -z "${BASH_VERSION:-}" ]; then
    echo "[X] VolDump debe ejecutarse con Bash: bash VolDump.sh" >&2
    exit 1
fi

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "[X] VolDump necesita Bash 4.4 o superior (versión actual: ${BASH_VERSION})." >&2
    exit 1
fi

set -o errexit
set -o nounset
set -o pipefail
umask 027

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

readonly APP_NAME="VolDump"
readonly APP_VERSION="10.1"

readonly EXIT_FATAL=1
readonly EXIT_USAGE=2
readonly EXIT_PARTIAL=3
readonly EXIT_INTERRUPTED=130

VOLDUMP_HOME="${VOLDUMP_HOME:-${XDG_DATA_HOME:-${HOME:-/root}/.local/share}/voldump}"
readonly VOL3_VENV="${VOLDUMP_HOME}/venv3"
readonly VOL2_DIR="${VOLDUMP_HOME}/volatility2"
readonly VOL2_REPO="https://github.com/volatilityfoundation/volatility.git"
readonly VOL2_TARBALL="https://github.com/volatilityfoundation/volatility/archive/refs/heads/master.tar.gz"

# Patrón de líneas de stderr que no indican un error real.
readonly RUIDO_STDERR='^(Volatility Foundation Volatility Framework|Volatility 3 Framework|Progress:|[[:space:]]*$)'

# Catálogo de plugins: so|id|categoría|plugin de Volatility 3|plugin de Volatility 2
#  - En Volatility 3 se pueden indicar alternativas separadas por comas: se usa la
#    primera que exista en la versión instalada (los nombres cambian entre versiones).
#  - "-" indica que ese motor no tiene un plugin equivalente.
readonly CATALOGO='
windows|info|general|windows.info|imageinfo
windows|pslist|procesos|windows.pslist|pslist
windows|psscan|procesos|windows.psscan|psscan
windows|pstree|procesos|windows.pstree|pstree
windows|cmdline|procesos|windows.cmdline|cmdline
windows|envars|procesos|windows.envars|envars
windows|getsids|procesos|windows.getsids|getsids
windows|privs|procesos|windows.privileges|privs
windows|cmdscan|usuario|windows.cmdscan|cmdscan
windows|consoles|usuario|windows.consoles|consoles
windows|userassist|usuario|windows.registry.userassist|userassist
windows|shimcache|usuario|windows.shimcachemem|shimcache
windows|amcache|usuario|windows.registry.amcache,windows.amcache|amcache
windows|iehistory|usuario|-|iehistory
windows|dlllist|modulos|windows.dlllist|dlllist
windows|modules|modulos|windows.modules|modules
windows|modscan|modulos|windows.modscan|modscan
windows|driverscan|modulos|windows.driverscan|driverscan
windows|netscan|red|windows.netscan|netscan
windows|netstat|red|windows.netstat|-
windows|connscan|red|-|connscan
windows|sockets|red|-|sockets
windows|filescan|archivos|windows.filescan|filescan
windows|handles|archivos|windows.handles|handles
windows|mutantscan|archivos|windows.mutantscan|mutantscan
windows|hivelist|registro|windows.registry.hivelist|hivelist
windows|run_hklm|registro|windows.registry.printkey --key Microsoft\Windows\CurrentVersion\Run|printkey -K Microsoft\Windows\CurrentVersion\Run
windows|run_hkcu|registro|windows.registry.printkey --key Software\Microsoft\Windows\CurrentVersion\Run|printkey -K Software\Microsoft\Windows\CurrentVersion\Run
windows|shellbags|registro|-|shellbags
windows|svcscan|persistencia|windows.svcscan|svcscan
windows|schtasks|persistencia|windows.registry.scheduled_tasks,windows.scheduled_tasks|-
windows|malfind|malware|windows.malware.malfind,windows.malfind|malfind
windows|psxview|malware|windows.malware.psxview,windows.psxview|psxview
windows|ldrmodules|malware|windows.malware.ldrmodules,windows.ldrmodules|ldrmodules
windows|hollow|malware|windows.malware.hollowprocesses,windows.hollowprocesses|-
windows|ssdt|malware|windows.ssdt|ssdt
windows|callbacks|malware|windows.callbacks|callbacks
windows|timeliner|timeline|timeliner.Timeliner|timeliner
linux|banners|general|banners.Banners|linux_banner
linux|boottime|general|linux.boottime|-
linux|pslist|procesos|linux.pslist|linux_pslist
linux|psscan|procesos|linux.psscan|-
linux|pstree|procesos|linux.pstree|linux_pstree
linux|psaux|procesos|linux.psaux|linux_psaux
linux|envars|procesos|linux.envars|linux_psenv
linux|bash|usuario|linux.bash|linux_bash
linux|lsmod|modulos|linux.lsmod|linux_lsmod
linux|sockstat|red|linux.sockstat|linux_netstat
linux|interfaces|red|linux.ip.Addr|linux_ifconfig
linux|lsof|archivos|linux.lsof|linux_lsof
linux|mountinfo|sistema|linux.mountinfo|linux_mount
linux|kmsg|sistema|linux.kmsg|linux_dmesg
linux|check_syscall|malware|linux.malware.check_syscall,linux.check_syscall|linux_check_syscall
linux|check_modules|malware|linux.malware.check_modules,linux.check_modules|linux_check_modules
linux|hidden_modules|malware|linux.malware.hidden_modules,linux.hidden_modules|linux_hidden_modules
linux|malfind|malware|linux.malware.malfind,linux.malfind|linux_malfind
linux|check_creds|malware|linux.malware.check_creds,linux.check_creds|linux_check_creds
linux|check_afinfo|malware|linux.malware.check_afinfo,linux.check_afinfo|linux_check_afinfo
linux|tty_check|malware|linux.malware.tty_check,linux.tty_check|linux_check_tty
linux|netfilter|malware|linux.malware.netfilter,linux.netfilter|linux_netfilter
linux|ebpf|malware|linux.ebpf|-
linux|timeliner|timeline|timeliner.Timeliner|-
mac|banners|general|banners.Banners|-
mac|pslist|procesos|mac.pslist|mac_pslist
mac|pstree|procesos|mac.pstree|mac_pstree
mac|psaux|procesos|mac.psaux|mac_psaux
mac|bash|usuario|mac.bash|mac_bash
mac|lsmod|modulos|mac.lsmod|mac_lsmod
mac|netstat|red|mac.netstat|mac_netstat
mac|ifconfig|red|mac.ifconfig|mac_ifconfig
mac|lsof|archivos|mac.lsof|mac_lsof
mac|list_files|archivos|mac.list_files|mac_list_files
mac|mount|sistema|mac.mount|mac_mount
mac|dmesg|sistema|mac.dmesg|mac_dmesg
mac|malfind|malware|mac.malfind|mac_malfind
mac|check_syscall|malware|mac.check_syscall|mac_check_syscalls
mac|check_sysctl|malware|mac.check_sysctl|mac_check_sysctl
mac|check_trap_table|malware|mac.check_trap_table|mac_check_trap_table
mac|socket_filters|malware|mac.socket_filters|mac_socket_filters
mac|timeliner|timeline|timeliner.Timeliner|-
'

readonly CATEGORY_ORDER=(general procesos usuario modulos red archivos registro persistencia sistema malware timeline)
declare -rA CATEGORY_LABEL=(
    [general]="Información general del sistema"
    [procesos]="Procesos, línea de comandos y privilegios"
    [usuario]="Actividad de usuario (consolas, historial, ejecuciones)"
    [modulos]="Módulos, DLLs y drivers"
    [red]="Red y conexiones"
    [archivos]="Archivos, handles y objetos"
    [registro]="Registro de Windows"
    [persistencia]="Servicios y persistencia"
    [sistema]="Sistema (montajes y mensajes del kernel)"
    [malware]="Malware, rootkits y anomalías"
    [timeline]="Línea temporal (lento)"
)

# ---------------------------------------------------------------------------
# Opciones y estado global
# ---------------------------------------------------------------------------

OPT_FILE=""
OPT_LIVE=false
OPT_ACQUIRE=false
OPT_OUTPUT=""
OPT_CATEGORIES=""
OPT_OS=""
OPT_ENGINE="auto"
OPT_ENGINE_SET=false
OPT_PROFILE=""
OPT_VOL2_PLUGINS=""
OPT_SYMBOLS=""
OPT_OFFLINE=false
OPT_FORMAT="text"
OPT_TIMEOUT=0
OPT_JOBS=1
OPT_VOL3="${VOLDUMP_VOL3:-}"
OPT_VOL2="${VOLDUMP_VOL2:-}"
OPT_INSTALL_VOL2=false
OPT_NO_INSTALL=false
OPT_HASH=true
OPT_LIST=false
OPT_YES=false
OPT_COLOR=true
INTERACTIVE=true
COMMAND_LINE=""

RED="" GREEN="" YELLOW="" BLUE="" BOLD="" NC=""

RUN_TMP=""
SESSION_LOG=""
LOG_FILE=""
SUDO=""
FINAL_EXIT=0

declare -a VOL3_CMD=() VOL3_PLUGINS=() VOL3_EXTRA_ARGS=()
VOL3_HELP=""
VOL3_VERSION=""
VOL3_LABEL=""

declare -a VOL2_CMD=() VOL2_PLUGINS=() VOL2_PROFILES=()
VOL2_VERSION=""
VOL2_LABEL=""
VOL2_INFO_LOADED=false

declare -a CAT_OS=() CAT_ID=() CAT_CAT=() CAT_V3=() CAT_V2=()

# Estado de cada análisis (se reinicia con reset_estado_analisis)
ANALYSIS_ACTIVE=false
INTERRUPTED=false
EVIDENCE_DIR=""
STATE_DIR=""
TARGET_PATH=""
TARGET_KIND=""
TARGET_LABEL=""
TARGET_SIZE=""
ACQUIRED_FILE=""
DETECTED_OS=""
OS_DETAIL=""
ENGINE=""
VOL2_PROFILE=""
VOL2_PROFILE_SOURCE=""
VOL2_READY=false
HASH_MD5_ANTES=""
HASH_SHA_ANTES=""
HASH_MD5_DESPUES=""
HASH_SHA_DESPUES=""
HASH_ESTADO=""
WININFO_FILE=""
BANNERS_FILE=""
IMAGEINFO_FILE=""
START_EPOCH=0
START_HUMAN=""
END_EPOCH=0
RUN_TOTAL=0
RUN_OK=0
RUN_FAIL=0
ENTRY_OK=0
ENTRY_FAIL=0
RUTA_ELEGIDA=""
declare -A DETECTION_CACHE=()
declare -a SELECTED_CATEGORIES=() SELECTED_ENTRIES=() PLAN=() PLAN_V3=() PLAN_V2=()
declare -a NO_DISPONIBLES=() FILAS_RESULTADOS=() FALLOS=() AVISOS=()

# ---------------------------------------------------------------------------
# Utilidades generales
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
${APP_NAME} ${APP_VERSION} - análisis forense de memoria con Volatility 3 y Volatility 2

Uso:
  ./VolDump.sh                          Asistente interactivo
  ./VolDump.sh -f VOLCADO [opciones]    Analiza un volcado sin hacer preguntas
  sudo ./VolDump.sh --live [opciones]   Analiza la memoria de este equipo (Linux)

Objetivo:
  -f, --file RUTA          Volcado de memoria a analizar.
      --live               Analiza la memoria del equipo en ejecución (Linux, root).
      --acquire            Con --live: adquiere antes la memoria con AVML (recomendado).

Análisis:
  -c, --categories LISTA   Categorías separadas por comas (por defecto: all):
                           general, procesos, usuario, modulos, red, archivos,
                           registro, persistencia, sistema, malware, timeline, all
                           ("all" incluye todo salvo timeline, que es muy lento).
      --os SO              Fuerza el sistema del volcado: windows, linux o mac.
  -e, --engine MOTOR       auto (por defecto): Volatility 3 y Volatility 2 como respaldo
                           vol3: solo Volatility 3 · vol2: solo Volatility 2
                           both: ejecuta los dos motores para contrastar resultados
  -p, --profile PERFIL     Perfil de Volatility 2 (p. ej. Win7SP1x64). En Windows se
                           deduce automáticamente si no se indica.
      --vol2-plugins DIR   Carpeta con plugins o perfiles propios de Volatility 2.
  -s, --symbols DIR        Carpeta de símbolos ISF para Volatility 3.
      --offline            Volatility 3 no descarga símbolos de Internet.
  -r, --format FORMATO     Salida de Volatility 3: text (por defecto), json o csv.
  -t, --timeout SEG        Tiempo máximo por plugin en segundos (0 = sin límite).
  -j, --jobs N             Número de plugins en paralelo (por defecto: 1).
  -o, --output DIR         Directorio de evidencias (por defecto: evidencias_FECHA).
      --no-hash            No calcula MD5/SHA-256 del volcado.

Herramientas:
      --vol3 RUTA          Ejecutable de Volatility 3 que se debe usar.
      --vol2 RUTA          Ejecutable de Volatility 2 (vol.py o binario standalone).
      --install-vol2       Instala Volatility 2 si no está disponible.
      --no-install         No instala nada automáticamente.

Otros:
      --list               Muestra el catálogo de plugins y sale.
  -y, --yes                Acepta automáticamente las confirmaciones.
      --no-color           Desactiva los colores.
  -V, --version            Muestra la versión.
  -h, --help               Muestra esta ayuda.

Variables de entorno: VOLDUMP_HOME, VOLDUMP_VOL3, VOLDUMP_VOL2, NO_COLOR.
Códigos de salida: 0 correcto, 1 error, 2 uso incorrecto, 3 algún plugin falló,
130 interrumpido.
EOF
}

usage_error() {
    printf '%s[X] %s%s\n' "${RED}" "$1" "${NC}" >&2
    printf 'Usa "%s --help" para ver las opciones.\n' "$0" >&2
    exit "${EXIT_USAGE}"
}

setup_colors() {
    if [[ "${OPT_COLOR}" == true && -z "${NO_COLOR:-}" && -t 1 && -t 2 ]]; then
        RED=$'\033[0;31m'
        GREEN=$'\033[0;32m'
        YELLOW=$'\033[1;33m'
        BLUE=$'\033[0;34m'
        BOLD=$'\033[1m'
        NC=$'\033[0m'
    else
        RED="" GREEN="" YELLOW="" BLUE="" BOLD="" NC=""
    fi
}

# Escribe un mensaje en pantalla (stderr, para no contaminar capturas) y,
# sin códigos de color, en el log del análisis.
log_line() {
    local level="$1" tag color ts
    shift
    case "${level}" in
        ok) tag="[OK]"; color="${GREEN}" ;;
        warn) tag="[!]"; color="${YELLOW}" ;;
        error) tag="[X]"; color="${RED}" ;;
        *) tag="[*]"; color="" ;;
    esac
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf '%s - %s%s %s%s\n' "${ts}" "${color}" "${tag}" "$*" "${color:+${NC}}" >&2
    if [[ -n "${LOG_FILE}" ]]; then
        printf '%s - %s %s\n' "${ts}" "${tag}" "$*" >>"${LOG_FILE}" 2>/dev/null || true
    fi
}

log_info() { log_line info "$@"; }
log_ok() { log_line ok "$@"; }
log_warn() { log_line warn "$@"; }
log_error() { log_line error "$@"; }

die() {
    log_error "$1"
    exit "${2:-${EXIT_FATAL}}"
}

recortar() {
    local valor="$1"
    valor="${valor#"${valor%%[![:space:]]*}"}"
    valor="${valor%"${valor##*[![:space:]]}"}"
    printf '%s' "${valor}"
}

# Lee una respuesta del usuario. Si la entrada termina (EOF) se informa en lugar
# de salir en silencio.
preguntar() {
    local __destino="$1" __texto="$2" __defecto="${3:-}" __respuesta=""
    if ! IFS= read -r -p "${__texto}" __respuesta; then
        printf '\n' >&2
        die "No hay más entrada disponible (EOF). Para usar VolDump sin preguntas usa -f o --live (ver --help)."
    fi
    __respuesta=$(recortar "${__respuesta}")
    if [[ -z "${__respuesta}" ]]; then
        __respuesta="${__defecto}"
    fi
    printf -v "${__destino}" '%s' "${__respuesta}"
}

# confirmar "pregunta" [s|n]: devuelve 0 si la respuesta es afirmativa.
confirmar() {
    local texto="$1" defecto="${2:-n}" respuesta pista="[s/N]"
    if [[ "${OPT_YES}" == true ]]; then
        return 0
    fi
    if [[ "${INTERACTIVE}" == false ]]; then
        [[ "${defecto}" == "s" ]]
        return
    fi
    if [[ "${defecto}" == "s" ]]; then
        pista="[S/n]"
    fi
    preguntar respuesta "${texto} ${pista} " "${defecto}"
    [[ "${respuesta,,}" =~ ^(s|si|sí|y|yes)$ ]]
}

# Normaliza una ruta escrita por el usuario: quita comillas (arrastrar y soltar),
# expande "~" y la convierte en absoluta.
# shellcheck disable=SC2088  # se compara con una "~" literal a propósito
normalizar_ruta() {
    local ruta
    ruta=$(recortar "$1")
    if [[ "${ruta}" =~ ^\'(.*)\'$ || "${ruta}" =~ ^\"(.*)\"$ ]]; then
        ruta="${BASH_REMATCH[1]}"
    fi
    if [[ "${ruta}" == "~" ]]; then
        ruta="${HOME}"
    elif [[ "${ruta}" == "~/"* ]]; then
        ruta="${HOME}/${ruta#"~/"}"
    fi
    if [[ ! -e "${ruta}" && "${ruta}" == *'\ '* ]]; then
        ruta="${ruta//\\ / }"
    fi
    if [[ -n "${ruta}" && "${ruta}" != /* ]]; then
        ruta="${PWD}/${ruta}"
    fi
    realpath -m -- "${ruta}" 2>/dev/null || printf '%s\n' "${ruta}"
}

fmt_duracion() {
    local s="$1"
    if (( s >= 3600 )); then
        printf '%dh %02dm %02ds' $((s / 3600)) $((s % 3600 / 60)) $((s % 60))
    elif (( s >= 60 )); then
        printf '%dm %02ds' $((s / 60)) $((s % 60))
    else
        printf '%ds' "${s}"
    fi
}

fmt_tamano() {
    local bytes="$1" legible
    if legible=$(numfmt --to=iec-i --suffix=B "${bytes}" 2>/dev/null); then
        printf '%s (%s bytes)' "${legible}" "${bytes}"
    else
        printf '%s bytes' "${bytes}"
    fi
}

en_lista() {
    local buscado="$1" elemento
    shift
    for elemento in "$@"; do
        if [[ "${elemento}" == "${buscado}" ]]; then
            return 0
        fi
    done
    return 1
}

nombre_so() {
    case "$1" in
        windows) printf 'Windows' ;;
        linux) printf 'Linux' ;;
        mac) printf 'macOS' ;;
        *) printf 'Desconocido' ;;
    esac
}

nombre_motor() {
    case "$1" in
        vol3) printf 'Volatility 3' ;;
        vol2) printf 'Volatility 2' ;;
        *) printf '%s' "$1" ;;
    esac
}

describir_motor() {
    case "${ENGINE}" in
        auto) printf 'Automático (Volatility 3 y Volatility 2 como respaldo)' ;;
        vol3) printf 'Solo Volatility 3' ;;
        vol2) printf 'Solo Volatility 2' ;;
        both) printf 'Ambos motores (resultados contrastados)' ;;
        *) printf 'No definido' ;;
    esac
}

renderer_vol3() {
    case "${OPT_FORMAT}" in
        json) printf 'json' ;;
        csv) printf 'csv' ;;
        *) printf 'quick' ;;
    esac
}

# Última línea significativa de un fichero de errores.
ultima_linea_error() {
    local fichero="$1" linea=""
    if [[ -f "${fichero}" ]]; then
        linea=$(grep -vE "${RUIDO_STDERR}" "${fichero}" | tail -n 1) || true
    fi
    printf '%s' "${linea:0:300}"
}

# Mata un proceso y todos sus descendientes.
# shellcheck disable=SC2317,SC2329  # se invoca desde el trap de interrupción
matar_arbol() {
    local pid="$1" hijo
    for hijo in $(pgrep -P "${pid}" 2>/dev/null || true); do
        matar_arbol "${hijo}"
    done
    kill -TERM "${pid}" 2>/dev/null || true
}

# shellcheck disable=SC2317,SC2329  # se invoca desde el trap de interrupción
detener_trabajos() {
    local pid
    for pid in $(jobs -pr); do
        matar_arbol "${pid}"
    done
}

print_banner() {
    printf '%s' "${BLUE}"
    printf '=============================================\n'
    printf '     VOLDUMP %-5s - VOLATILITY 3 + 2         \n' "${APP_VERSION}"
    printf '                 By: Mayky                   \n'
    printf '=============================================\n'
    printf '%s\n' "${NC}"
}

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------

requiere_valor() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        usage_error "La opción $1 necesita un valor."
    fi
}

citar_argumento() {
    if [[ "$1" =~ ^[A-Za-z0-9_./:=,@%+-]+$ ]]; then
        printf '%s' "$1"
    else
        printf '%q' "$1"
    fi
}

parse_args() {
    local argumento
    COMMAND_LINE=$(citar_argumento "$0")
    for argumento in "$@"; do
        COMMAND_LINE+=" $(citar_argumento "${argumento}")"
    done

    while [[ $# -gt 0 ]]; do
        if [[ "$1" == --*=* ]]; then
            set -- "${1%%=*}" "${1#*=}" "${@:2}"
        fi
        case "$1" in
            -h|--help) usage; exit 0 ;;
            -V|--version) printf '%s %s\n' "${APP_NAME}" "${APP_VERSION}"; exit 0 ;;
            -f|--file) requiere_valor "$@"; OPT_FILE="$2"; shift 2 ;;
            --live) OPT_LIVE=true; shift ;;
            --acquire) OPT_ACQUIRE=true; OPT_LIVE=true; shift ;;
            -o|--output) requiere_valor "$@"; OPT_OUTPUT="$2"; shift 2 ;;
            -c|--categories) requiere_valor "$@"; OPT_CATEGORIES="$2"; shift 2 ;;
            --os) requiere_valor "$@"; OPT_OS="${2,,}"; shift 2 ;;
            -e|--engine) requiere_valor "$@"; OPT_ENGINE="${2,,}"; OPT_ENGINE_SET=true; shift 2 ;;
            -p|--profile) requiere_valor "$@"; OPT_PROFILE="$2"; shift 2 ;;
            --vol2-plugins) requiere_valor "$@"; OPT_VOL2_PLUGINS="$2"; shift 2 ;;
            -s|--symbols) requiere_valor "$@"; OPT_SYMBOLS="$2"; shift 2 ;;
            --offline) OPT_OFFLINE=true; shift ;;
            -r|--format) requiere_valor "$@"; OPT_FORMAT="${2,,}"; shift 2 ;;
            -t|--timeout) requiere_valor "$@"; OPT_TIMEOUT="$2"; shift 2 ;;
            -j|--jobs) requiere_valor "$@"; OPT_JOBS="$2"; shift 2 ;;
            --vol3) requiere_valor "$@"; OPT_VOL3="$2"; shift 2 ;;
            --vol2) requiere_valor "$@"; OPT_VOL2="$2"; shift 2 ;;
            --install-vol2) OPT_INSTALL_VOL2=true; shift ;;
            --no-install) OPT_NO_INSTALL=true; shift ;;
            --no-hash) OPT_HASH=false; shift ;;
            --list) OPT_LIST=true; shift ;;
            -y|--yes) OPT_YES=true; shift ;;
            --no-color) OPT_COLOR=false; shift ;;
            --) shift; break ;;
            -*) usage_error "Opción desconocida: $1" ;;
            *) usage_error "Argumento inesperado: $1" ;;
        esac
    done
    if [[ $# -gt 0 ]]; then
        usage_error "Argumento inesperado: $1"
    fi

    case "${OPT_ENGINE}" in
        auto|vol3|vol2|both) ;;
        *) usage_error "Motor no válido: ${OPT_ENGINE} (usa auto, vol3, vol2 o both)." ;;
    esac
    case "${OPT_FORMAT}" in
        text|json|csv) ;;
        *) usage_error "Formato no válido: ${OPT_FORMAT} (usa text, json o csv)." ;;
    esac
    case "${OPT_OS}" in
        "") ;;
        windows|win) OPT_OS="windows" ;;
        linux) OPT_OS="linux" ;;
        mac|macos|osx) OPT_OS="mac" ;;
        *) usage_error "Sistema no válido: ${OPT_OS} (usa windows, linux o mac)." ;;
    esac
    [[ "${OPT_TIMEOUT}" =~ ^[0-9]+$ ]] || usage_error "--timeout debe ser un número entero de segundos."
    [[ "${OPT_JOBS}" =~ ^[1-9][0-9]*$ ]] || usage_error "--jobs debe ser un número entero mayor que 0."
    if [[ -n "${OPT_FILE}" && "${OPT_LIVE}" == true ]]; then
        usage_error "-f y --live no se pueden usar a la vez."
    fi
    if [[ -n "${OPT_SYMBOLS}" ]]; then
        OPT_SYMBOLS=$(normalizar_ruta "${OPT_SYMBOLS}")
        [[ -d "${OPT_SYMBOLS}" ]] || usage_error "La carpeta de símbolos no existe: ${OPT_SYMBOLS}"
    fi
    if [[ -n "${OPT_VOL2_PLUGINS}" ]]; then
        OPT_VOL2_PLUGINS=$(normalizar_ruta "${OPT_VOL2_PLUGINS}")
        [[ -d "${OPT_VOL2_PLUGINS}" ]] || usage_error "La carpeta de plugins de Volatility 2 no existe: ${OPT_VOL2_PLUGINS}"
    fi
    if [[ -n "${OPT_FILE}" || "${OPT_LIVE}" == true ]]; then
        INTERACTIVE=false
    fi

    VOL3_EXTRA_ARGS=()
    if [[ -n "${OPT_SYMBOLS}" ]]; then
        VOL3_EXTRA_ARGS+=(-s "${OPT_SYMBOLS}")
    fi
    if [[ "${OPT_OFFLINE}" == true ]]; then
        VOL3_EXTRA_ARGS+=(--offline)
    fi
}

# ---------------------------------------------------------------------------
# Entorno y paquetes del sistema
# ---------------------------------------------------------------------------

check_runtime() {
    local host_os
    host_os=$(uname -s)
    if [[ "${host_os}" != "Linux" ]]; then
        die "VolDump está diseñado para ejecutarse en Linux (sistema detectado: ${host_os})."
    fi
    if [[ "${EUID}" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
}

run_privileged() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    elif [[ -n "${SUDO}" ]]; then
        sudo "$@"
    else
        log_error "Se necesitan permisos de administrador (root o sudo) para: $*"
        return 1
    fi
}

detectar_gestor() {
    local gestor
    for gestor in apt-get dnf microdnf yum zypper pacman apk; do
        if command -v "${gestor}" >/dev/null 2>&1; then
            printf '%s\n' "${gestor}"
            return 0
        fi
    done
    return 1
}

# Traduce un paquete lógico (python3, venv, python2, git) al nombre de cada gestor.
nombre_paquete() {
    case "$1:$2" in
        apt-get:venv) printf 'python3-venv' ;;
        apt-get:python2|dnf:python2|microdnf:python2|yum:python2) printf 'python2' ;;
        zypper:python2) printf 'python' ;;
        pacman:python3|pacman:venv) printf 'python' ;;
        pacman:python2|apk:python2) return 1 ;;
        *:python3|*:venv) printf 'python3' ;;
        *:git) printf 'git' ;;
        *) return 1 ;;
    esac
}

instalar_paquete() {
    local logico="$1" gestor paquete
    if [[ "${OPT_NO_INSTALL}" == true ]]; then
        log_warn "Instalación automática desactivada (--no-install)."
        return 1
    fi
    if ! gestor=$(detectar_gestor); then
        log_warn "No se encontró un gestor de paquetes compatible para instalar '${logico}'."
        return 1
    fi
    if ! paquete=$(nombre_paquete "${gestor}" "${logico}"); then
        log_warn "No hay paquete '${logico}' disponible para ${gestor}."
        return 1
    fi
    log_info "Instalando ${paquete} con ${gestor}..."
    case "${gestor}" in
        apt-get)
            run_privileged apt-get update -qq &&
                run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${paquete}"
            ;;
        dnf|microdnf|yum) run_privileged "${gestor}" install -y "${paquete}" ;;
        zypper) run_privileged zypper --non-interactive install "${paquete}" ;;
        pacman) run_privileged pacman -S --needed --noconfirm "${paquete}" ;;
        apk) run_privileged apk add --no-cache "${paquete}" ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Dependencias: Python y Volatility 3
# ---------------------------------------------------------------------------

verificar_python() {
    local version
    log_info "Verificando Python 3..."
    if ! command -v python3 >/dev/null 2>&1; then
        log_warn "Python 3 no está instalado."
        if confirmar "¿Instalar Python 3 con el gestor de paquetes del sistema?" s; then
            instalar_paquete python3 || true
        fi
        command -v python3 >/dev/null 2>&1 || die "Python 3 es necesario y no se pudo instalar. Instálalo manualmente y vuelve a ejecutar VolDump."
    fi
    version=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
        die "Se requiere Python 3.8 o superior (versión detectada: ${version})."
    fi
    log_ok "Python ${version} detectado."
}

# Comprueba que un comando es Volatility 3 y guarda su ayuda (versión y plugins).
probar_volatility3() {
    local salida
    salida=$("$@" -h 2>&1) || true
    if [[ "${salida}" == *"Volatility 3 Framework"* ]]; then
        VOL3_HELP="${salida}"
        return 0
    fi
    return 1
}

home_usuario_real() {
    local entrada
    if [[ -n "${SUDO_USER:-}" ]] && entrada=$(getent passwd "${SUDO_USER}" 2>/dev/null); then
        entrada="${entrada#*:*:*:*:*:}"
        printf '%s\n' "${entrada%%:*}"
    fi
}

buscar_volatility3() {
    local candidato home_real
    local -a candidatos=(vol vol3 volatility3 "${HOME}/.local/bin/vol" "${VOL3_VENV}/bin/vol")
    VOL3_CMD=()

    if [[ -n "${OPT_VOL3}" ]]; then
        if [[ "${OPT_VOL3}" == *.py ]] && probar_volatility3 python3 "${OPT_VOL3}"; then
            VOL3_CMD=(python3 "${OPT_VOL3}")
        elif probar_volatility3 "${OPT_VOL3}"; then
            VOL3_CMD=("${OPT_VOL3}")
        else
            die "'${OPT_VOL3}' no parece un ejecutable de Volatility 3."
        fi
        VOL3_LABEL="${OPT_VOL3}"
        return 0
    fi

    home_real=$(home_usuario_real)
    if [[ -n "${home_real}" ]]; then
        candidatos+=("${home_real}/.local/bin/vol")
    fi
    for candidato in "${candidatos[@]}"; do
        if [[ "${candidato}" == */* ]]; then
            [[ -x "${candidato}" ]] || continue
        else
            candidato=$(command -v "${candidato}" 2>/dev/null) || continue
        fi
        if probar_volatility3 "${candidato}"; then
            VOL3_CMD=("${candidato}")
            VOL3_LABEL="${candidato}"
            return 0
        fi
    done

    # Instalado como módulo de Python pero sin el script "vol" en el PATH.
    # "python3 -m volatility3" no funciona (el paquete no tiene __main__) y
    # Volatility 3 analiza sys.argv[0], así que se fija a "vol" antes de main().
    local lanzador='import sys; sys.argv[0] = "vol"; from volatility3.cli import main; main()'
    if python3 -c 'import volatility3.cli' >/dev/null 2>&1 && probar_volatility3 python3 -c "${lanzador}"; then
        VOL3_CMD=(python3 -c "${lanzador}")
        VOL3_LABEL="módulo de Python (volatility3.cli)"
        return 0
    fi
    return 1
}

cargar_info_vol3() {
    VOL3_VERSION=""
    if [[ "${VOL3_HELP}" =~ Volatility\ 3\ Framework\ ([0-9][0-9.]*) ]]; then
        VOL3_VERSION="${BASH_REMATCH[1]}"
    fi
    mapfile -t VOL3_PLUGINS < <(printf '%s\n' "${VOL3_HELP}" | grep -oE '^ +[a-z][a-z0-9_]*(\.[A-Za-z0-9_]+)+' | tr -d ' ' | sort -u)
}

# Instala Volatility 3 en un entorno virtual propio. Evita el error
# "externally-managed-environment" (PEP 668) de Debian, Ubuntu, Kali, Arch...
instalar_volatility3() {
    local py="${VOL3_VENV}/bin/python"
    mkdir -p -- "${VOLDUMP_HOME}" || return 1
    if [[ ! -x "${py}" ]]; then
        log_info "Creando entorno virtual en ${VOL3_VENV}..."
        if ! python3 -m venv "${VOL3_VENV}"; then
            rm -rf -- "${VOL3_VENV}"
            log_warn "El módulo venv de Python no está disponible."
            instalar_paquete venv || return 1
            python3 -m venv "${VOL3_VENV}" || return 1
        fi
    fi
    "${py}" -m pip install --quiet --upgrade pip setuptools wheel || log_warn "No se pudo actualizar pip dentro del entorno virtual."
    log_info "Instalando volatility3[full] (puede tardar unos minutos)..."
    if "${py}" -m pip install 'volatility3[full]'; then
        return 0
    fi
    log_warn "La instalación con extras falló. Probando con el paquete base de Volatility 3..."
    "${py}" -m pip install volatility3
}

verificar_volatility3() {
    log_info "Buscando Volatility 3..."
    if buscar_volatility3; then
        cargar_info_vol3
        log_ok "Volatility 3 ${VOL3_VERSION:-(versión desconocida)} disponible: ${VOL3_LABEL}"
        return 0
    fi
    log_warn "Volatility 3 no está instalado."
    if [[ "${OPT_NO_INSTALL}" == true ]]; then
        return 1
    fi
    if ! confirmar "¿Instalar Volatility 3 en un entorno virtual propio (${VOL3_VENV})?" s; then
        return 1
    fi
    if instalar_volatility3 && buscar_volatility3; then
        cargar_info_vol3
        log_ok "Volatility 3 ${VOL3_VERSION} instalado en ${VOL3_VENV}."
        return 0
    fi
    log_error "No se pudo instalar Volatility 3."
    return 1
}

# ---------------------------------------------------------------------------
# Dependencias: Volatility 2
# ---------------------------------------------------------------------------

buscar_python2() {
    local candidato
    for candidato in python2 python2.7; do
        if command -v "${candidato}" >/dev/null 2>&1; then
            command -v "${candidato}"
            return 0
        fi
    done
    if command -v python >/dev/null 2>&1 &&
        python -c 'import sys; sys.exit(0 if sys.version_info[0] == 2 else 1)' >/dev/null 2>&1; then
        command -v python
        return 0
    fi
    return 1
}

probar_volatility2() {
    local salida
    salida=$("$@" -h 2>&1) || true
    if [[ "${salida}" =~ Volatility\ Framework\ (2\.[0-9.]+) ]]; then
        VOL2_VERSION="${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

# Prueba un candidato a Volatility 2; los scripts .py se lanzan con Python 2.
probar_candidato_vol2() {
    local ruta="$1" py2
    if [[ "${ruta}" == *.py ]] && py2=$(buscar_python2); then
        if probar_volatility2 "${py2}" "${ruta}"; then
            VOL2_CMD=("${py2}" "${ruta}")
            return 0
        fi
    fi
    if [[ -x "${ruta}" ]] && probar_volatility2 "${ruta}"; then
        VOL2_CMD=("${ruta}")
        return 0
    fi
    return 1
}

buscar_volatility2() {
    local candidato ruta
    VOL2_CMD=()
    VOL2_INFO_LOADED=false

    if [[ -n "${OPT_VOL2}" ]]; then
        ruta=$(normalizar_ruta "${OPT_VOL2}")
        if [[ ! -e "${ruta}" ]]; then
            ruta=$(command -v "${OPT_VOL2}" 2>/dev/null) || die "No se encuentra Volatility 2 en '${OPT_VOL2}'."
        fi
        probar_candidato_vol2 "${ruta}" || die "'${OPT_VOL2}' no parece un ejecutable de Volatility 2."
        VOL2_LABEL="${ruta}"
        return 0
    fi

    for candidato in vol.py vol2 vol2.py volatility2 volatility; do
        ruta=$(command -v "${candidato}" 2>/dev/null) || continue
        if probar_candidato_vol2 "${ruta}"; then
            VOL2_LABEL="${ruta}"
            return 0
        fi
    done
    if [[ -f "${VOL2_DIR}/vol.py" ]] && probar_candidato_vol2 "${VOL2_DIR}/vol.py"; then
        VOL2_LABEL="${VOL2_DIR}/vol.py"
        return 0
    fi
    return 1
}

instalar_volatility2() {
    local py2
    if ! py2=$(buscar_python2); then
        log_warn "Volatility 2 necesita Python 2.7."
        if confirmar "¿Intentar instalar Python 2 con el gestor de paquetes?" s; then
            instalar_paquete python2 || true
        fi
        if ! py2=$(buscar_python2); then
            log_error "Python 2.7 no está disponible (muchas distribuciones modernas ya no lo incluyen). Puedes usar el binario standalone de Volatility 2 con --vol2 RUTA."
            return 1
        fi
    fi
    mkdir -p -- "${VOLDUMP_HOME}" || return 1
    if [[ ! -f "${VOL2_DIR}/vol.py" ]]; then
        rm -rf -- "${VOL2_DIR}"
        log_info "Descargando Volatility 2 en ${VOL2_DIR}..."
        if ! command -v git >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
            instalar_paquete git || true
        fi
        if command -v git >/dev/null 2>&1; then
            git clone --quiet --depth 1 "${VOL2_REPO}" "${VOL2_DIR}" || return 1
        elif command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
            mkdir -p -- "${VOL2_DIR}"
            if command -v curl >/dev/null 2>&1; then
                curl -fsSL "${VOL2_TARBALL}" | tar -xz --strip-components=1 -C "${VOL2_DIR}" || return 1
            else
                wget -qO- "${VOL2_TARBALL}" | tar -xz --strip-components=1 -C "${VOL2_DIR}" || return 1
            fi
        else
            log_error "Se necesita git, curl o wget para descargar Volatility 2."
            return 1
        fi
    fi
    if "${py2}" -m pip --version >/dev/null 2>&1; then
        log_info "Instalando dependencias opcionales de Volatility 2 (distorm3, pycrypto)..."
        "${py2}" -m pip install --quiet --user distorm3==3.4.4 pycrypto >/dev/null 2>&1 ||
            log_warn "No se pudieron instalar distorm3/pycrypto: algunos plugins de Volatility 2 darán menos detalle."
    fi
    return 0
}

verificar_volatility2() {
    local instalar=false
    log_info "Buscando Volatility 2..."
    if buscar_volatility2; then
        log_ok "Volatility 2 ${VOL2_VERSION} disponible: ${VOL2_LABEL}"
        return 0
    fi
    if [[ "${OPT_NO_INSTALL}" == false ]]; then
        if [[ "${OPT_INSTALL_VOL2}" == true || "${OPT_ENGINE}" == vol2 || "${OPT_ENGINE}" == both ]]; then
            if confirmar "Volatility 2 no está disponible. ¿Instalarlo en ${VOL2_DIR}?" s; then
                instalar=true
            fi
        elif [[ "${INTERACTIVE}" == true ]] && buscar_python2 >/dev/null; then
            if confirmar "Volatility 2 no está instalado. ¿Quieres instalarlo para combinarlo con Volatility 3?" n; then
                instalar=true
            fi
        fi
    fi
    if [[ "${instalar}" == true ]]; then
        if instalar_volatility2 && buscar_volatility2; then
            log_ok "Volatility 2 ${VOL2_VERSION} instalado en ${VOL2_DIR}."
            return 0
        fi
        log_warn "No se pudo instalar Volatility 2."
    else
        log_info "Volatility 2 no disponible: se usará solo Volatility 3 (añádelo con --vol2 RUTA o --install-vol2)."
    fi
    return 1
}

# Carga la lista de perfiles y plugins de Volatility 2 (vol.py --info).
cargar_info_vol2() {
    local salida
    local -a args=()
    if [[ "${VOL2_INFO_LOADED}" == true ]]; then
        return 0
    fi
    if [[ -n "${OPT_VOL2_PLUGINS}" ]]; then
        args+=("--plugins=${OPT_VOL2_PLUGINS}")
    fi
    if ! salida=$("${VOL2_CMD[@]}" "${args[@]}" --info 2>/dev/null); then
        log_warn "No se pudo obtener la información de Volatility 2 (--info)."
        return 1
    fi
    mapfile -t VOL2_PROFILES < <(printf '%s\n' "${salida}" | awk '/^Profiles$/ {s = 1; getline; next} s && /^[[:space:]]*$/ {s = 0} s {print $1}')
    mapfile -t VOL2_PLUGINS < <(printf '%s\n' "${salida}" | awk '/^Plugins$/ {s = 1; getline; next} s && /^[[:space:]]*$/ {s = 0} s {print $1}')
    VOL2_INFO_LOADED=true
}

verificar_dependencias() {
    local hay_vol3=true
    verificar_python
    verificar_volatility3 || hay_vol3=false
    verificar_volatility2 || true
    if [[ "${hay_vol3}" == false && ${#VOL2_CMD[@]} -eq 0 ]]; then
        die "No hay ningún motor de Volatility disponible. Instala Volatility 3 (pip install volatility3) o indica uno con --vol3/--vol2."
    fi
}

# ---------------------------------------------------------------------------
# Catálogo
# ---------------------------------------------------------------------------

cargar_catalogo() {
    local so id categoria v3 v2
    CAT_OS=() CAT_ID=() CAT_CAT=() CAT_V3=() CAT_V2=()
    while IFS='|' read -r so id categoria v3 v2; do
        if [[ -z "${so}" || "${so}" == \#* ]]; then
            continue
        fi
        CAT_OS+=("${so}")
        CAT_ID+=("${id}")
        CAT_CAT+=("${categoria}")
        CAT_V3+=("${v3}")
        CAT_V2+=("${v2}")
    done <<<"${CATALOGO}"
}

mostrar_catalogo() {
    local so i
    for so in windows linux mac; do
        printf '\n%s%s%s\n' "${BOLD}" "$(nombre_so "${so}")" "${NC}"
        printf '  %-13s %-16s %-48s %s\n' "CATEGORIA" "ID" "VOLATILITY 3" "VOLATILITY 2"
        for i in "${!CAT_ID[@]}"; do
            if [[ "${CAT_OS[i]}" == "${so}" ]]; then
                printf '  %-13s %-16s %-48s %s\n' "${CAT_CAT[i]}" "${CAT_ID[i]}" "${CAT_V3[i]}" "${CAT_V2[i]}"
            fi
        done
    done
    printf '\n'
}

resolver_plugin_vol3() {
    local alternativas="$1" alternativa plugin
    local -a lista=()
    if [[ ${#VOL3_CMD[@]} -eq 0 ]]; then
        return 1
    fi
    IFS=',' read -r -a lista <<<"${alternativas}"
    if [[ ${#VOL3_PLUGINS[@]} -eq 0 ]]; then
        printf '%s\n' "${lista[0]}"
        return 0
    fi
    for alternativa in "${lista[@]}"; do
        for plugin in "${VOL3_PLUGINS[@]}"; do
            if [[ "${plugin}" == "${alternativa}" || "${plugin}" == "${alternativa}."* ]]; then
                printf '%s\n' "${alternativa}"
                return 0
            fi
        done
    done
    return 1
}

plugin_vol2_disponible() {
    if [[ ${#VOL2_PLUGINS[@]} -eq 0 ]]; then
        return 0
    fi
    en_lista "$1" "${VOL2_PLUGINS[@]}"
}

# ---------------------------------------------------------------------------
# Espacio de trabajo e integridad
# ---------------------------------------------------------------------------

reset_estado_analisis() {
    ANALYSIS_ACTIVE=false
    INTERRUPTED=false
    EVIDENCE_DIR=""
    STATE_DIR=""
    TARGET_PATH=""
    TARGET_KIND=""
    TARGET_LABEL=""
    TARGET_SIZE=""
    ACQUIRED_FILE=""
    DETECTED_OS=""
    OS_DETAIL=""
    ENGINE=""
    VOL2_PROFILE=""
    VOL2_PROFILE_SOURCE=""
    VOL2_READY=false
    HASH_MD5_ANTES=""
    HASH_SHA_ANTES=""
    HASH_MD5_DESPUES=""
    HASH_SHA_DESPUES=""
    HASH_ESTADO=""
    WININFO_FILE=""
    BANNERS_FILE=""
    IMAGEINFO_FILE=""
    DETECTION_CACHE=()
    SELECTED_CATEGORIES=()
    SELECTED_ENTRIES=()
    PLAN=()
    PLAN_V3=()
    PLAN_V2=()
    NO_DISPONIBLES=()
    FILAS_RESULTADOS=()
    FALLOS=()
    AVISOS=()
    RUN_TOTAL=0
    RUN_OK=0
    RUN_FAIL=0
    ENTRY_OK=0
    ENTRY_FAIL=0
    START_EPOCH=$(date +%s)
    START_HUMAN=$(date '+%Y-%m-%d %H:%M:%S')
    END_EPOCH=0
}

preparar_espacio_trabajo() {
    local base candidato sufijo=2
    if [[ -n "${OPT_OUTPUT}" ]]; then
        base=$(normalizar_ruta "${OPT_OUTPUT}")
    else
        base="${PWD}/evidencias_$(date +%Y%m%d_%H%M%S)"
    fi
    candidato="${base}"
    while [[ -e "${candidato}" && -n "$(ls -A -- "${candidato}" 2>/dev/null)" ]]; do
        candidato="${base}_${sufijo}"
        sufijo=$((sufijo + 1))
    done
    EVIDENCE_DIR="${candidato}"
    mkdir -p -- "${EVIDENCE_DIR}/logs/errores" "${EVIDENCE_DIR}/resultados" ||
        die "No se pudo crear el directorio de evidencias: ${EVIDENCE_DIR}"
    STATE_DIR=$(mktemp -d "${RUN_TMP}/estado.XXXXXX")
    LOG_FILE="${EVIDENCE_DIR}/logs/voldump.log"
    cat -- "${SESSION_LOG}" >"${LOG_FILE}" 2>/dev/null || : >"${LOG_FILE}"
    log_info "Directorio de evidencias: ${EVIDENCE_DIR}"
}

iniciar_analisis() {
    reset_estado_analisis
    preparar_espacio_trabajo
    ANALYSIS_ACTIVE=true
}

# Imprime "md5 sha256" leyendo el fichero una sola vez.
calcular_hashes() {
    local fichero="$1" md5 sha
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${fichero}" <<'PYEOF'
import hashlib
import sys

try:
    md5 = hashlib.new("md5", usedforsecurity=False)
except TypeError:
    md5 = hashlib.md5()
sha256 = hashlib.sha256()
with open(sys.argv[1], "rb") as fh:
    for bloque in iter(lambda: fh.read(8 * 1024 * 1024), b""):
        md5.update(bloque)
        sha256.update(bloque)
print(md5.hexdigest(), sha256.hexdigest())
PYEOF
    else
        md5=$(md5sum -- "${fichero}")
        sha=$(sha256sum -- "${fichero}")
        printf '%s %s\n' "${md5%% *}" "${sha%% *}"
    fi
}

calcular_hashes_iniciales() {
    if [[ "${OPT_HASH}" == false ]]; then
        log_info "Cálculo de hashes desactivado (--no-hash)."
        return 0
    fi
    log_info "Calculando MD5 y SHA-256 del volcado (puede tardar en volcados grandes)..."
    read -r HASH_MD5_ANTES HASH_SHA_ANTES < <(calcular_hashes "${TARGET_PATH}") || true
    if [[ -z "${HASH_SHA_ANTES}" ]]; then
        log_warn "No se pudieron calcular los hashes del volcado."
        return 0
    fi
    printf '%s  %s\n' "${HASH_SHA_ANTES}" "${TARGET_PATH}" >"${EVIDENCE_DIR}/hashes.sha256"
    printf '%s  %s\n' "${HASH_MD5_ANTES}" "${TARGET_PATH}" >"${EVIDENCE_DIR}/hashes.md5"
    log_ok "SHA-256: ${HASH_SHA_ANTES}"
}

verificar_integridad() {
    if [[ "${OPT_HASH}" == false || -z "${HASH_SHA_ANTES}" ]]; then
        return 0
    fi
    log_info "Verificando la integridad del volcado tras el análisis..."
    read -r HASH_MD5_DESPUES HASH_SHA_DESPUES < <(calcular_hashes "${TARGET_PATH}") || true
    if [[ "${HASH_SHA_DESPUES}" == "${HASH_SHA_ANTES}" ]]; then
        HASH_ESTADO="coincide"
        log_ok "Integridad verificada: el SHA-256 no ha cambiado."
    else
        HASH_ESTADO="NO coincide"
        log_error "El SHA-256 del volcado ha cambiado durante el análisis."
    fi
}

restaurar_propietario() {
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && -n "${EVIDENCE_DIR}" && -d "${EVIDENCE_DIR}" ]]; then
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${EVIDENCE_DIR}" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Ejecución de Volatility
# ---------------------------------------------------------------------------

run_with_timeout() {
    if (( OPT_TIMEOUT > 0 )) && command -v timeout >/dev/null 2>&1; then
        timeout --foreground --kill-after=15 "${OPT_TIMEOUT}" "$@"
    else
        "$@"
    fi
}

# run_vol3 ORIGEN SALIDA ERRORES RENDERER PLUGIN [ARGS...]
run_vol3() {
    local origen="$1" salida="$2" errores="$3" renderer="$4"
    shift 4
    run_with_timeout "${VOL3_CMD[@]}" -q "${VOL3_EXTRA_ARGS[@]}" -r "${renderer}" -f "${origen}" "$@" >"${salida}" 2>"${errores}"
}

# run_vol2 ORIGEN SALIDA ERRORES PLUGIN [ARGS...]
run_vol2() {
    local origen="$1" salida="$2" errores="$3"
    local -a args=()
    shift 3
    # --plugins debe ir siempre en primer lugar en Volatility 2.
    if [[ -n "${OPT_VOL2_PLUGINS}" ]]; then
        args+=("--plugins=${OPT_VOL2_PLUGINS}")
    fi
    if [[ -n "${VOL2_PROFILE}" ]]; then
        args+=("--profile=${VOL2_PROFILE}")
    fi
    run_with_timeout "${VOL2_CMD[@]}" "${args[@]}" -f "${origen}" "$@" >"${salida}" 2>"${errores}"
}

# Borra un fichero de errores si solo contiene ruido (banner, progreso...).
limpiar_si_vacio() {
    local fichero="$1"
    if [[ -f "${fichero}" ]] && ! grep -qvE "${RUIDO_STDERR}" "${fichero}"; then
        rm -f -- "${fichero}"
    fi
}

guardar_error_deteccion() {
    local errores="$1" nombre="$2" linea
    if [[ -s "${errores}" && -n "${EVIDENCE_DIR}" ]]; then
        cp -- "${errores}" "${EVIDENCE_DIR}/logs/errores/deteccion_${nombre}.err" 2>/dev/null || true
    fi
    linea=$(ultima_linea_error "${errores}")
    if [[ -n "${linea}" ]]; then
        log_info "  ${nombre}: ${linea}"
    fi
}

# ---------------------------------------------------------------------------
# Detección del sistema operativo y perfiles de Volatility 2
# ---------------------------------------------------------------------------

perfil_desde_imageinfo() {
    local linea
    linea=$(grep -m 1 'Suggested Profile(s)' "$1" 2>/dev/null) || return 1
    linea="${linea#*: }"
    linea="${linea%%,*}"
    linea="${linea// /}"
    if [[ -z "${linea}" || "${linea}" == No* ]]; then
        return 1
    fi
    printf '%s\n' "${linea}"
}

# Rellena DETECTED_OS. No se llama con $(...) para que los mensajes de log no
# se mezclen con el resultado.
detectar_so() {
    local origen="$1" salida errores perfil
    DETECTED_OS=""

    if [[ ${#VOL3_CMD[@]} -gt 0 ]]; then
        log_info "Detectando el sistema operativo con Volatility 3 (windows.info)..."
        salida="${RUN_TMP}/deteccion_windows_info.txt"
        errores="${RUN_TMP}/deteccion_windows_info.err"
        if run_vol3 "${origen}" "${salida}" "${errores}" quick windows.info && grep -q '^Kernel Base' "${salida}"; then
            DETECTED_OS="windows"
            WININFO_FILE="${salida}"
            if [[ "${OPT_FORMAT}" == text ]]; then
                DETECTION_CACHE["vol3:windows.info"]="${salida}"
            fi
            return 0
        fi
        guardar_error_deteccion "${errores}" windows_info

        log_info "No parece Windows. Buscando banners de Linux o macOS (banners.Banners)..."
        salida="${RUN_TMP}/deteccion_banners.txt"
        errores="${RUN_TMP}/deteccion_banners.err"
        if run_vol3 "${origen}" "${salida}" "${errores}" quick banners.Banners; then
            if grep -q 'Darwin Kernel Version' "${salida}"; then
                DETECTED_OS="mac"
            elif grep -q 'Linux version' "${salida}"; then
                DETECTED_OS="linux"
            fi
            if [[ -n "${DETECTED_OS}" ]]; then
                BANNERS_FILE="${salida}"
                if [[ "${OPT_FORMAT}" == text ]]; then
                    DETECTION_CACHE["vol3:banners.Banners"]="${salida}"
                fi
                return 0
            fi
        else
            guardar_error_deteccion "${errores}" banners
        fi
    fi

    if [[ ${#VOL2_CMD[@]} -gt 0 ]]; then
        log_info "Probando con Volatility 2 (imageinfo, puede tardar varios minutos)..."
        salida="${RUN_TMP}/deteccion_imageinfo.txt"
        errores="${RUN_TMP}/deteccion_imageinfo.err"
        if run_vol2 "${origen}" "${salida}" "${errores}" imageinfo && perfil=$(perfil_desde_imageinfo "${salida}"); then
            DETECTED_OS="windows"
            IMAGEINFO_FILE="${salida}"
            DETECTION_CACHE["vol2:imageinfo"]="${salida}"
            log_info "Volatility 2 sugiere el perfil ${perfil}."
            return 0
        fi
        guardar_error_deteccion "${errores}" imageinfo
    fi
    return 1
}

pedir_so_manual() {
    local opcion
    printf '\nNo se pudo detectar el sistema operativo del volcado.\n'
    printf '  1. Windows\n  2. Linux\n  3. macOS\n  4. Cancelar\n'
    while true; do
        preguntar opcion "¿Qué sistema es? "
        case "${opcion}" in
            1) DETECTED_OS="windows"; return 0 ;;
            2) DETECTED_OS="linux"; return 0 ;;
            3) DETECTED_OS="mac"; return 0 ;;
            4) return 1 ;;
            *) log_warn "Opción no válida: ${opcion}" ;;
        esac
    done
}

campo_info() {
    awk -F'\t' -v clave="$2" '$1 == clave {print $2; exit}' "$1" 2>/dev/null || true
}

describir_so() {
    local lab arch build tiempo banner
    OS_DETAIL=""
    if [[ "${TARGET_KIND}" == vivo ]]; then
        OS_DETAIL="$(uname -srm)"
    elif [[ "${DETECTED_OS}" == windows && -n "${WININFO_FILE}" ]]; then
        lab=$(campo_info "${WININFO_FILE}" NTBuildLab)
        build=$(campo_info "${WININFO_FILE}" "Major/Minor")
        tiempo=$(campo_info "${WININFO_FILE}" SystemTime)
        arch="x86"
        if [[ "$(campo_info "${WININFO_FILE}" Is64Bit)" == True ]]; then
            arch="x64"
        fi
        OS_DETAIL="Windows NT $(campo_info "${WININFO_FILE}" NtMajorVersion).$(campo_info "${WININFO_FILE}" NtMinorVersion) build ${build#*.} ${arch}"
        if [[ -n "${lab}" ]]; then
            OS_DETAIL+=" (${lab})"
        fi
        if [[ -n "${tiempo}" ]]; then
            OS_DETAIL+=", hora del sistema en la captura: ${tiempo}"
        fi
    elif [[ -n "${BANNERS_FILE}" ]]; then
        banner=$(grep -m 1 -oE '(Linux version|Darwin Kernel Version)[^[:cntrl:]]*' "${BANNERS_FILE}" 2>/dev/null) || true
        OS_DETAIL="${banner:0:200}"
    elif [[ -n "${IMAGEINFO_FILE}" ]]; then
        OS_DETAIL="Perfil sugerido por imageinfo: $(perfil_desde_imageinfo "${IMAGEINFO_FILE}" || true)"
    fi
    if [[ -n "${OS_DETAIL}" ]]; then
        log_info "Detalle del sistema: ${OS_DETAIL}"
    fi
}

# Elige el perfil de Volatility 2 más adecuado entre los instalados.
# Para Windows 10/Server 2016 usa el build más cercano por debajo.
elegir_perfil_vol2() {
    local base="$1" build="${2:-0}" perfil num mejor="" mejor_num=-1 minimo="" minimo_num=999999 prefijo=""
    local con_build=false
    if [[ "${base}" == Win10* || "${base}" == Win2016* ]]; then
        con_build=true
    fi
    for perfil in "${VOL2_PROFILES[@]}"; do
        if [[ "${con_build}" == true ]]; then
            if [[ "${perfil}" == "${base}" ]]; then
                num=10240
            elif [[ "${perfil}" == "${base}_"* ]]; then
                num="${perfil#"${base}_"}"
                num="${num%%_*}"
                [[ "${num}" =~ ^[0-9]+$ ]] || continue
            else
                continue
            fi
            if (( num <= build && num > mejor_num )); then
                mejor="${perfil}"
                mejor_num="${num}"
            fi
            if (( num < minimo_num )); then
                minimo="${perfil}"
                minimo_num="${num}"
            fi
        else
            if [[ "${perfil}" == "${base}" ]]; then
                printf '%s\n' "${perfil}"
                return 0
            fi
            if [[ -z "${prefijo}" && "${perfil}" == "${base}"* ]]; then
                prefijo="${perfil}"
            fi
        fi
    done
    if [[ "${con_build}" == true ]]; then
        if [[ -n "${mejor}" ]]; then
            printf '%s\n' "${mejor}"
            return 0
        fi
        if [[ -n "${minimo}" ]]; then
            printf '%s\n' "${minimo}"
            return 0
        fi
        return 1
    fi
    if [[ -n "${prefijo}" ]]; then
        printf '%s\n' "${prefijo}"
        return 0
    fi
    return 1
}

# Deduce el perfil de Volatility 2 a partir de la salida de windows.info.
derivar_perfil_windows() {
    local fichero="$1" major minor csd producto build arch="x86" servidor=false base perfil
    major=$(campo_info "${fichero}" NtMajorVersion)
    minor=$(campo_info "${fichero}" NtMinorVersion)
    csd=$(campo_info "${fichero}" CSDVersion)
    producto=$(campo_info "${fichero}" NtProductType)
    build=$(campo_info "${fichero}" "Major/Minor")
    build="${build#*.}"
    [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]] || return 1
    [[ "${csd}" =~ ^[0-9]+$ ]] || csd=0
    [[ "${build}" =~ ^[0-9]+$ ]] || build=0
    if [[ "$(campo_info "${fichero}" Is64Bit)" == True ]]; then
        arch="x64"
    fi
    if [[ -n "${producto}" && "${producto}" != *WinNt* ]]; then
        servidor=true
    fi

    case "${major}.${minor}" in
        5.1)
            if (( csd < 2 )); then csd=2; fi
            base="WinXPSP${csd}x86"
            ;;
        5.2)
            if [[ "${servidor}" == false && "${arch}" == x64 ]]; then
                base="WinXPSP2x64"
            else
                if [[ "${arch}" == x64 ]] && (( csd < 1 )); then csd=1; fi
                base="Win2003SP${csd}${arch}"
            fi
            ;;
        6.0)
            if [[ "${servidor}" == true ]]; then
                if (( csd < 1 )); then csd=1; fi
                base="Win2008SP${csd}${arch}"
            else
                base="VistaSP${csd}${arch}"
            fi
            ;;
        6.1)
            if [[ "${servidor}" == true ]]; then base="Win2008R2SP${csd}x64"; else base="Win7SP${csd}${arch}"; fi
            ;;
        6.2)
            if [[ "${servidor}" == true ]]; then base="Win2012x64"; else base="Win8SP0${arch}"; fi
            ;;
        6.3)
            if [[ "${servidor}" == true ]]; then base="Win2012R2x64"; else base="Win81U1${arch}"; fi
            ;;
        10.0)
            if [[ "${servidor}" == true ]]; then base="Win2016x64"; else base="Win10${arch}"; fi
            ;;
        *) return 1 ;;
    esac

    perfil=$(elegir_perfil_vol2 "${base}" "${build}") || return 1
    VOL2_PROFILE="${perfil}"
    VOL2_PROFILE_SOURCE="deducido de windows.info"
    if [[ "${base}" == Win10* || "${base}" == Win2016* ]] && [[ "${perfil}" != *"_${build}"* ]]; then
        VOL2_PROFILE_SOURCE+=", aproximado: no hay perfil exacto para el build ${build}"
    fi
    return 0
}

# Deja Volatility 2 listo (perfil incluido) para el objetivo actual.
preparar_volatility2() {
    local salida errores perfil
    VOL2_READY=false
    if [[ ${#VOL2_CMD[@]} -eq 0 ]] || ! cargar_info_vol2; then
        return 1
    fi

    if [[ -n "${OPT_PROFILE}" ]]; then
        VOL2_PROFILE="${OPT_PROFILE}"
        VOL2_PROFILE_SOURCE="indicado con --profile"
        if [[ ${#VOL2_PROFILES[@]} -gt 0 ]] && ! en_lista "${VOL2_PROFILE}" "${VOL2_PROFILES[@]}"; then
            log_warn "El perfil ${VOL2_PROFILE} no aparece en 'vol.py --info'; se intentará igualmente."
        fi
    elif [[ "${DETECTED_OS}" == windows ]]; then
        if [[ -n "${WININFO_FILE}" ]] && derivar_perfil_windows "${WININFO_FILE}"; then
            :
        elif [[ -n "${IMAGEINFO_FILE}" ]] && perfil=$(perfil_desde_imageinfo "${IMAGEINFO_FILE}"); then
            VOL2_PROFILE="${perfil}"
            VOL2_PROFILE_SOURCE="sugerido por imageinfo"
        else
            log_info "Buscando el perfil de Volatility 2 con imageinfo (puede tardar)..."
            salida="${RUN_TMP}/perfil_imageinfo.txt"
            errores="${RUN_TMP}/perfil_imageinfo.err"
            if run_vol2 "${TARGET_PATH}" "${salida}" "${errores}" imageinfo && perfil=$(perfil_desde_imageinfo "${salida}"); then
                VOL2_PROFILE="${perfil}"
                VOL2_PROFILE_SOURCE="sugerido por imageinfo"
                IMAGEINFO_FILE="${salida}"
                DETECTION_CACHE["vol2:imageinfo"]="${salida}"
            fi
        fi
    else
        log_warn "Volatility 2 necesita un perfil para $(nombre_so "${DETECTED_OS}") (usa --profile y, si es propio, --vol2-plugins)."
        return 1
    fi

    if [[ -z "${VOL2_PROFILE}" ]]; then
        log_warn "No se pudo determinar el perfil de Volatility 2 (indícalo con --profile)."
        return 1
    fi
    log_ok "Perfil de Volatility 2: ${VOL2_PROFILE} (${VOL2_PROFILE_SOURCE})."
    VOL2_READY=true
}

# ---------------------------------------------------------------------------
# Motor y selección de categorías
# ---------------------------------------------------------------------------

elegir_motor() {
    local hay_vol3=false opcion
    if [[ ${#VOL3_CMD[@]} -gt 0 ]]; then
        hay_vol3=true
    fi
    ENGINE="${OPT_ENGINE}"

    if [[ "${TARGET_KIND}" == vivo ]]; then
        if [[ "${ENGINE}" == vol2 || "${ENGINE}" == both ]]; then
            log_warn "Volatility 2 no puede analizar /proc/kcore; se usará Volatility 3."
        fi
        [[ "${hay_vol3}" == true ]] || die "El análisis en vivo necesita Volatility 3."
        ENGINE="vol3"
        log_info "Motor de análisis: $(describir_motor)"
        return 0
    fi

    if [[ "${ENGINE}" != vol3 && ${#VOL2_CMD[@]} -gt 0 ]]; then
        preparar_volatility2 || true
    fi

    if [[ "${INTERACTIVE}" == true && "${OPT_ENGINE_SET}" == false && "${hay_vol3}" == true && "${VOL2_READY}" == true ]]; then
        printf '\n%sMotor de análisis:%s\n' "${BLUE}" "${NC}"
        printf '  1. Automático: Volatility 3 y, si un plugin falla o solo existe en Volatility 2, Volatility 2 (recomendado)\n'
        printf '  2. Solo Volatility 3\n'
        printf '  3. Solo Volatility 2\n'
        printf '  4. Ambos: ejecuta los dos motores para contrastar resultados\n'
        while true; do
            preguntar opcion "Opción [1]: " 1
            case "${opcion}" in
                1) ENGINE="auto"; break ;;
                2) ENGINE="vol3"; break ;;
                3) ENGINE="vol2"; break ;;
                4) ENGINE="both"; break ;;
                *) log_warn "Opción no válida: ${opcion}" ;;
            esac
        done
    fi

    case "${ENGINE}" in
        vol2)
            [[ "${VOL2_READY}" == true ]] || die "Se pidió Volatility 2, pero no está disponible o no tiene perfil para este volcado."
            ;;
        both)
            if [[ "${VOL2_READY}" != true ]]; then
                log_warn "Volatility 2 no está listo para este volcado; se usará solo Volatility 3."
                ENGINE="vol3"
            elif [[ "${hay_vol3}" == false ]]; then
                log_warn "Volatility 3 no está disponible; se usará solo Volatility 2."
                ENGINE="vol2"
            fi
            ;;
    esac
    if [[ "${ENGINE}" == auto || "${ENGINE}" == vol3 ]] && [[ "${hay_vol3}" == false ]]; then
        if [[ "${VOL2_READY}" == true ]]; then
            log_warn "Volatility 3 no está disponible; se usará solo Volatility 2."
            ENGINE="vol2"
        else
            die "No hay ningún motor de Volatility capaz de analizar este volcado."
        fi
    fi
    log_info "Motor de análisis: $(describir_motor)"
}

categorias_disponibles() {
    local so="$1" categoria i
    for categoria in "${CATEGORY_ORDER[@]}"; do
        for i in "${!CAT_ID[@]}"; do
            if [[ "${CAT_OS[i]}" == "${so}" && "${CAT_CAT[i]}" == "${categoria}" ]]; then
                printf '%s\n' "${categoria}"
                break
            fi
        done
    done
}

contar_plugins() {
    local so="$1" categoria="$2" i total=0
    for i in "${!CAT_ID[@]}"; do
        if [[ "${CAT_OS[i]}" == "${so}" && "${CAT_CAT[i]}" == "${categoria}" ]]; then
            total=$((total + 1))
        fi
    done
    printf '%s' "${total}"
}

# Convierte la selección del usuario (números o nombres) en SELECTED_CATEGORIES.
parsear_categorias() {
    local entrada="$1" token categoria todo=false
    local -a disponibles=() elegidas=() invalidos=() tokens=()
    mapfile -t disponibles < <(categorias_disponibles "${DETECTED_OS}")
    read -r -a tokens <<<"${entrada//,/ }"
    for token in "${tokens[@]}"; do
        token="${token,,}"
        if [[ "${token}" =~ ^[0-9]+$ ]]; then
            if (( token >= 1 && token <= ${#disponibles[@]} )); then
                elegidas+=("${disponibles[token - 1]}")
            elif (( token == ${#disponibles[@]} + 1 )); then
                todo=true
            else
                invalidos+=("${token}")
            fi
        elif [[ "${token}" == all || "${token}" == todo || "${token}" == todos ]]; then
            todo=true
        elif en_lista "${token}" "${disponibles[@]}"; then
            elegidas+=("${token}")
        elif [[ -n "${CATEGORY_LABEL[${token}]:-}" ]]; then
            invalidos+=("${token} (no aplica a $(nombre_so "${DETECTED_OS}"))")
        else
            invalidos+=("${token}")
        fi
    done
    if [[ ${#invalidos[@]} -gt 0 ]]; then
        log_warn "Selección no válida: ${invalidos[*]}"
        return 1
    fi
    if [[ "${todo}" == true ]]; then
        for categoria in "${disponibles[@]}"; do
            if [[ "${categoria}" != timeline ]]; then
                elegidas+=("${categoria}")
            fi
        done
    fi
    SELECTED_CATEGORIES=()
    for categoria in "${disponibles[@]}"; do
        if [[ ${#elegidas[@]} -gt 0 ]] && en_lista "${categoria}" "${elegidas[@]}"; then
            SELECTED_CATEGORIES+=("${categoria}")
        fi
    done
    [[ ${#SELECTED_CATEGORIES[@]} -gt 0 ]]
}

seleccionar_categorias() {
    local entrada categoria i=0 n
    local -a disponibles=()
    mapfile -t disponibles < <(categorias_disponibles "${DETECTED_OS}")

    if [[ "${INTERACTIVE}" == true && -z "${OPT_CATEGORIES}" ]]; then
        printf '\n%sSelecciona qué quieres extraer (%s):%s\n' "${BLUE}" "$(nombre_so "${DETECTED_OS}")" "${NC}"
        for categoria in "${disponibles[@]}"; do
            i=$((i + 1))
            n=$(contar_plugins "${DETECTED_OS}" "${categoria}")
            printf '  %2d. %-58s [%s plugin%s]\n' "${i}" "${CATEGORY_LABEL[${categoria}]}" "${n}" "$([[ "${n}" == 1 ]] || printf 's')"
        done
        printf '  %2d. Todo (excepto la línea temporal)\n' $((i + 1))
        while true; do
            preguntar entrada "Escribe números o nombres separados por comas (p. ej. 1,2,5 o procesos,red): "
            if [[ -n "${entrada}" ]] && parsear_categorias "${entrada}"; then
                break
            fi
            log_warn "Debes elegir al menos una opción válida."
        done
    else
        parsear_categorias "${OPT_CATEGORIES:-all}" ||
            die "Las categorías indicadas no son válidas para $(nombre_so "${DETECTED_OS}")." "${EXIT_USAGE}"
    fi

    SELECTED_ENTRIES=()
    for i in "${!CAT_ID[@]}"; do
        if [[ "${CAT_OS[i]}" == "${DETECTED_OS}" ]] && en_lista "${CAT_CAT[i]}" "${SELECTED_CATEGORIES[@]}"; then
            SELECTED_ENTRIES+=("${i}")
        fi
    done
    log_info "Categorías seleccionadas: ${SELECTED_CATEGORIES[*]}"
}

motivo_no_disponible() {
    local idx="$1"
    local -a motivos=()
    if [[ "${CAT_V3[idx]}" == "-" ]]; then
        motivos+=("sin plugin en Volatility 3")
    elif [[ "${ENGINE}" == vol2 ]]; then
        motivos+=("Volatility 3 no seleccionado")
    elif [[ ${#VOL3_CMD[@]} -eq 0 ]]; then
        motivos+=("Volatility 3 no disponible")
    else
        motivos+=("no existe en Volatility 3 ${VOL3_VERSION}")
    fi
    if [[ "${CAT_V2[idx]}" == "-" ]]; then
        motivos+=("sin plugin en Volatility 2")
    elif [[ "${ENGINE}" == vol3 ]]; then
        motivos+=("Volatility 2 no seleccionado")
    elif [[ "${VOL2_READY}" != true ]]; then
        motivos+=("Volatility 2 no disponible o sin perfil")
    else
        motivos+=("no existe en Volatility 2 ${VOL2_VERSION}")
    fi
    printf '%s; %s' "${motivos[0]}" "${motivos[1]}"
}

# Decide qué motor(es) puede ejecutar cada plugin seleccionado.
planificar() {
    local idx v3 v2
    local -a palabras=()
    PLAN=()
    PLAN_V3=()
    PLAN_V2=()
    NO_DISPONIBLES=()
    for idx in "${SELECTED_ENTRIES[@]}"; do
        v3=""
        v2=""
        if [[ "${ENGINE}" != vol2 && "${CAT_V3[idx]}" != "-" ]]; then
            read -r -a palabras <<<"${CAT_V3[idx]}"
            v3=$(resolver_plugin_vol3 "${palabras[0]}") || v3=""
        fi
        if [[ "${ENGINE}" != vol3 && "${VOL2_READY}" == true && "${CAT_V2[idx]}" != "-" ]]; then
            read -r -a palabras <<<"${CAT_V2[idx]}"
            if plugin_vol2_disponible "${palabras[0]}"; then
                v2="${palabras[0]}"
            fi
        fi
        if [[ -z "${v3}" && -z "${v2}" ]]; then
            NO_DISPONIBLES+=("${CAT_ID[idx]}"$'\x1f'"${CAT_CAT[idx]}"$'\x1f'"$(motivo_no_disponible "${idx}")")
            continue
        fi
        PLAN+=("${idx}")
        PLAN_V3[idx]="${v3}"
        PLAN_V2[idx]="${v2}"
    done
    if [[ ${#NO_DISPONIBLES[@]} -gt 0 ]]; then
        log_info "${#NO_DISPONIBLES[@]} plugin(s) de la selección no están disponibles con el motor elegido (se detallan en el reporte)."
    fi
    [[ ${#PLAN[@]} -gt 0 ]] || die "Ninguno de los plugins seleccionados está disponible con el motor elegido."
}

# ---------------------------------------------------------------------------
# Ejecución de los plugins
# ---------------------------------------------------------------------------

# ejecutar_motor MOTOR IDX PLUGIN FICHERO_ESTADO POS TOTAL [NOTA]
# Devuelve 0 si el plugin terminó correctamente.
ejecutar_motor() {
    local motor="$1" idx="$2" plugin="$3" estado_file="$4" pos="$5" total="$6" nota="${7:-}"
    local id="${CAT_ID[idx]}" categoria="${CAT_CAT[idx]}" spec descripcion ext="txt" dir salida errores
    local inicio duracion rc=0 estado rel_err="" detalle clave
    local -a palabras=()

    if [[ "${motor}" == vol3 ]]; then
        spec="${CAT_V3[idx]}"
        case "${OPT_FORMAT}" in
            json) ext="json" ;;
            csv) ext="csv" ;;
        esac
    else
        spec="${CAT_V2[idx]}"
    fi
    read -r -a palabras <<<"${spec}"
    descripcion="${plugin}"
    if [[ ${#palabras[@]} -gt 1 ]]; then
        descripcion+=" ${palabras[*]:1}"
    fi

    dir="${EVIDENCE_DIR}/resultados/${categoria}"
    mkdir -p -- "${dir}"
    salida="${dir}/${id}.${motor}.${ext}"
    errores="${EVIDENCE_DIR}/logs/errores/${id}.${motor}.err"

    log_info "[${pos}/${total}] ${categoria} > ${descripcion} ($(nombre_motor "${motor}")${nota:+, ${nota}})"
    inicio=$(date +%s)
    clave="${motor}:${descripcion}"
    if [[ -n "${DETECTION_CACHE[${clave}]:-}" ]]; then
        cp -- "${DETECTION_CACHE[${clave}]}" "${salida}"
        : >"${errores}"
    elif [[ "${motor}" == vol3 ]]; then
        run_vol3 "${TARGET_PATH}" "${salida}" "${errores}" "$(renderer_vol3)" "${plugin}" "${palabras[@]:1}" || rc=$?
    else
        run_vol2 "${TARGET_PATH}" "${salida}" "${errores}" "${plugin}" "${palabras[@]:1}" || rc=$?
        # Volatility 2 no siempre devuelve un código de error al fallar.
        if (( rc == 0 )) && grep -qE '^(ERROR +:|Traceback \(most recent call last\))' "${errores}"; then
            rc=1
        fi
    fi
    duracion=$(( $(date +%s) - inicio ))

    case "${rc}" in
        0) estado="ok" ;;
        124|137) estado="timeout" ;;
        *) estado="error" ;;
    esac

    if [[ "${estado}" == ok ]]; then
        limpiar_si_vacio "${errores}"
        log_ok "[${pos}/${total}] ${descripcion} completado en $(fmt_duracion "${duracion}")."
    else
        limpiar_si_vacio "${salida}"
        if [[ "${estado}" == timeout ]]; then
            printf 'Tiempo máximo agotado (%ss).\n' "${OPT_TIMEOUT}" >>"${errores}"
        fi
        detalle=$(ultima_linea_error "${errores}")
        log_warn "[${pos}/${total}] ${descripcion} ($(nombre_motor "${motor}")) terminó con ${estado} (código ${rc})${detalle:+: ${detalle}}"
    fi
    if [[ -f "${errores}" ]]; then
        rel_err="${errores#"${EVIDENCE_DIR}/"}"
    fi
    if [[ ! -f "${salida}" ]]; then
        salida=""
    fi
    printf 'R\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
        "${id}" "${categoria}" "${motor}" "${descripcion}" "${estado}" "${duracion}" \
        "${salida#"${EVIDENCE_DIR}/"}" "${rel_err}" "${nota}" >>"${estado_file}"
    [[ "${estado}" == ok ]]
}

ejecutar_entrada() {
    local idx="$1" pos="$2" total="$3"
    local v3="${PLAN_V3[idx]:-}" v2="${PLAN_V2[idx]:-}" exito=false resultado="error" estado_file nota=""
    estado_file="${STATE_DIR}/$(printf '%04d' "${pos}").estado"

    case "${ENGINE}" in
        auto)
            if [[ -n "${v3}" ]] && ejecutar_motor vol3 "${idx}" "${v3}" "${estado_file}" "${pos}" "${total}"; then
                exito=true
            elif [[ -n "${v2}" ]]; then
                if [[ -n "${v3}" ]]; then
                    nota="respaldo"
                fi
                if ejecutar_motor vol2 "${idx}" "${v2}" "${estado_file}" "${pos}" "${total}" "${nota}"; then
                    exito=true
                fi
            fi
            ;;
        vol3)
            if ejecutar_motor vol3 "${idx}" "${v3}" "${estado_file}" "${pos}" "${total}"; then
                exito=true
            fi
            ;;
        vol2)
            if ejecutar_motor vol2 "${idx}" "${v2}" "${estado_file}" "${pos}" "${total}"; then
                exito=true
            fi
            ;;
        both)
            if [[ -n "${v3}" ]] && ejecutar_motor vol3 "${idx}" "${v3}" "${estado_file}" "${pos}" "${total}"; then
                exito=true
            fi
            if [[ -n "${v2}" ]] && ejecutar_motor vol2 "${idx}" "${v2}" "${estado_file}" "${pos}" "${total}"; then
                exito=true
            fi
            ;;
    esac
    if [[ "${exito}" == true ]]; then
        resultado="ok"
    fi
    printf 'E\x1f%s\x1f%s\x1f%s\n' "${CAT_ID[idx]}" "${CAT_CAT[idx]}" "${resultado}" >>"${estado_file}"
}

ejecutar_plan() {
    local total=${#PLAN[@]} pos=0 activos=0 idx
    if (( OPT_JOBS > 1 )); then
        log_info "Ejecutando ${total} plugins (${OPT_JOBS} en paralelo)..."
    else
        log_info "Ejecutando ${total} plugins..."
    fi
    if (( OPT_TIMEOUT > 0 )) && ! command -v timeout >/dev/null 2>&1; then
        log_warn "El comando 'timeout' no está disponible: no se aplicará --timeout."
    fi
    # Cada plugin se lanza como trabajo y se espera con "wait", que (a diferencia
    # de un comando en primer plano) deja actuar al trap ante Ctrl+C o SIGTERM.
    # Con -j 1 la ejecución sigue siendo secuencial.
    for idx in "${PLAN[@]}"; do
        pos=$((pos + 1))
        ejecutar_entrada "${idx}" "${pos}" "${total}" &
        activos=$((activos + 1))
        if (( activos >= OPT_JOBS )); then
            wait -n || true
            activos=$((activos - 1))
        fi
    done
    wait || true
}

# ---------------------------------------------------------------------------
# Informes
# ---------------------------------------------------------------------------

recopilar_resultados() {
    local fichero
    local -a campos=()
    RUN_TOTAL=0 RUN_OK=0 RUN_FAIL=0 ENTRY_OK=0 ENTRY_FAIL=0
    FILAS_RESULTADOS=()
    FALLOS=()
    if [[ -z "${STATE_DIR}" || ! -d "${STATE_DIR}" ]]; then
        return 0
    fi
    for fichero in "${STATE_DIR}"/*.estado; do
        [[ -f "${fichero}" ]] || continue
        while IFS=$'\x1f' read -r -a campos; do
            case "${campos[0]:-}" in
                R)
                    RUN_TOTAL=$((RUN_TOTAL + 1))
                    FILAS_RESULTADOS+=("$(IFS=$'\x1f'; printf '%s' "${campos[*]:1}")")
                    if [[ "${campos[5]:-}" == ok ]]; then
                        RUN_OK=$((RUN_OK + 1))
                    else
                        RUN_FAIL=$((RUN_FAIL + 1))
                        FALLOS+=("$(IFS=$'\x1f'; printf '%s' "${campos[*]:1}")")
                    fi
                    ;;
                E)
                    if [[ "${campos[3]:-}" == ok ]]; then
                        ENTRY_OK=$((ENTRY_OK + 1))
                    else
                        ENTRY_FAIL=$((ENTRY_FAIL + 1))
                    fi
                    ;;
            esac
        done <"${fichero}"
    done
}

generar_avisos() {
    local errores_dir="${EVIDENCE_DIR}/logs/errores"
    AVISOS=()
    if grep -qsE 'symbol_table_name|symbol table requirement|Unsatisfied requirement' "${errores_dir}"/*.vol3.err; then
        case "${DETECTED_OS}" in
            linux|mac)
                AVISOS+=("Volatility 3 no encontró símbolos (ISF) para este kernel. Genera un ISF con dwarf2json a partir del kernel con símbolos de depuración (${OS_DETAIL:-mismo banner}) y pásalo con -s DIR.")
                ;;
            windows)
                AVISOS+=("Volatility 3 necesita descargar los símbolos PDB de Microsoft la primera vez (requiere Internet) o usar -s DIR con símbolos ISF ya generados.")
                ;;
        esac
    fi
    if grep -qsE 'No suitable address space mapping found|Invalid profile|does not support the selected profile' "${errores_dir}"/*.vol2.err; then
        AVISOS+=("Algunos plugins de Volatility 2 fallaron por el perfil o el formato del volcado. Comprueba el perfil (${VOL2_PROFILE:-no definido}) o indícalo con --profile.")
    fi
    if [[ "${HASH_ESTADO}" == "NO coincide" ]]; then
        AVISOS+=("El SHA-256 del volcado cambió durante el análisis: revisa la cadena de custodia.")
    fi
    if [[ "${TARGET_KIND}" == vivo ]]; then
        AVISOS+=("El análisis de /proc/kcore es frágil (símbolos, lockdown del kernel). Para resultados reproducibles adquiere la memoria con AVML o LiME y analiza el fichero resultante.")
    fi
    if [[ "${OPT_FORMAT}" != text && ( "${ENGINE}" == vol2 || "${ENGINE}" == both || "${ENGINE}" == auto ) && "${VOL2_READY}" == true ]]; then
        AVISOS+=("Volatility 2 siempre genera texto; el formato ${OPT_FORMAT} solo se aplica a Volatility 3.")
    fi
    if [[ "${DETECTED_OS}" != windows && ${#VOL2_CMD[@]} -gt 0 && "${VOL2_READY}" != true && "${TARGET_KIND}" != vivo ]]; then
        AVISOS+=("Volatility 2 no se usó: para Linux y macOS necesita un perfil propio (--profile y --vol2-plugins).")
    fi
}

celda() {
    local valor="$1"
    valor="${valor//|/\\|}"
    valor="${valor//$'\n'/ }"
    printf '%s' "${valor}"
}

fila() {
    if [[ -n "$2" ]]; then
        printf '| %s | %s |\n' "$1" "$(celda "$2")"
    fi
}

estado_final_texto() {
    case "$1" in
        completado)
            if (( ENTRY_FAIL > 0 )); then
                printf 'Completado con errores'
            else
                printf 'Completado'
            fi
            ;;
        interrumpido) printf 'Interrumpido por el usuario' ;;
        *) printf 'Finalizado por un error' ;;
    esac
}

# shellcheck disable=SC2016  # las comillas invertidas son formato Markdown
generar_reporte() {
    local estado="$1" fila_datos tamano="" vol2_texto="no disponible" perfil="" i=0 aviso
    local -a c=()
    if [[ -n "${TARGET_SIZE}" ]]; then
        tamano=$(fmt_tamano "${TARGET_SIZE}")
    fi
    if [[ ${#VOL2_CMD[@]} -gt 0 ]]; then
        vol2_texto="${VOL2_VERSION} (${VOL2_LABEL})"
    fi
    if [[ -n "${VOL2_PROFILE}" ]]; then
        perfil="${VOL2_PROFILE} (${VOL2_PROFILE_SOURCE})"
    fi
    {
        printf '# Reporte VolDump\n\n'
        printf '| Campo | Valor |\n|---|---|\n'
        fila "Estado" "$(estado_final_texto "${estado}")"
        fila "Inicio" "${START_HUMAN}"
        fila "Fin" "$(date '+%Y-%m-%d %H:%M:%S')"
        fila "Duración" "$(fmt_duracion $((END_EPOCH - START_EPOCH)))"
        fila "Objetivo" "${TARGET_LABEL}"
        fila "Tamaño" "${tamano}"
        fila "Sistema operativo" "$(nombre_so "${DETECTED_OS}")"
        fila "Detalle del sistema" "${OS_DETAIL}"
        fila "Motor" "$(describir_motor)"
        fila "Volatility 3" "${VOL3_VERSION:+${VOL3_VERSION} (${VOL3_LABEL})}"
        fila "Volatility 2" "${vol2_texto}"
        fila "Perfil de Volatility 2" "${perfil}"
        fila "Formato de salida" "${OPT_FORMAT}"
        fila "Categorías" "${SELECTED_CATEGORIES[*]}"
        fila "Analista" "${SUDO_USER:-${USER:-$(id -un)}}@$(uname -n)"
        fila "Equipo de análisis" "$(uname -srm)"
        fila "VolDump" "${APP_VERSION}"
        fila "Comando" "${COMMAND_LINE}"
        printf '\n'

        if [[ -n "${HASH_SHA_ANTES}" ]]; then
            printf '## Integridad del volcado\n\n'
            printf '| Momento | MD5 | SHA-256 |\n|---|---|---|\n'
            printf '| Antes del análisis | `%s` | `%s` |\n' "${HASH_MD5_ANTES}" "${HASH_SHA_ANTES}"
            if [[ -n "${HASH_SHA_DESPUES}" ]]; then
                printf '| Después del análisis | `%s` | `%s` |\n' "${HASH_MD5_DESPUES}" "${HASH_SHA_DESPUES}"
            fi
            printf '\nResultado de la verificación: **%s**\n\n' "${HASH_ESTADO:-no verificado}"
        fi

        printf '## Resumen\n\n'
        printf -- '- Plugins planificados: %s\n' "${#PLAN[@]}"
        printf -- '- Plugins con resultado: %s\n' "${ENTRY_OK}"
        printf -- '- Plugins sin resultado: %s\n' "${ENTRY_FAIL}"
        printf -- '- Ejecuciones de Volatility: %s (correctas: %s, con errores: %s)\n\n' "${RUN_TOTAL}" "${RUN_OK}" "${RUN_FAIL}"

        printf '## Resultados por plugin\n\n'
        if [[ ${#FILAS_RESULTADOS[@]} -eq 0 ]]; then
            printf 'No se ejecutó ningún plugin.\n\n'
        else
            printf '| # | Categoría | Plugin | Motor | Estado | Duración | Salida |\n|---|---|---|---|---|---|---|\n'
            for fila_datos in "${FILAS_RESULTADOS[@]}"; do
                i=$((i + 1))
                IFS=$'\x1f' read -r -a c <<<"${fila_datos}"
                printf '| %s | %s | `%s` | %s%s | %s | %s | %s |\n' "${i}" "${c[1]}" "$(celda "${c[3]}")" \
                    "$(nombre_motor "${c[2]}")" "${c[8]:+ (${c[8]})}" "${c[4]}" "$(fmt_duracion "${c[5]}")" \
                    "${c[6]:+\`${c[6]}\`}"
            done
            printf '\n'
        fi

        if [[ ${#FALLOS[@]} -gt 0 ]]; then
            printf '## Errores\n\n'
            for fila_datos in "${FALLOS[@]}"; do
                IFS=$'\x1f' read -r -a c <<<"${fila_datos}"
                printf -- '- `%s` (%s, %s)' "$(celda "${c[3]}")" "$(nombre_motor "${c[2]}")" "${c[4]}"
                if [[ -n "${c[7]:-}" ]]; then
                    printf ': %s → `%s`' "$(celda "$(ultima_linea_error "${EVIDENCE_DIR}/${c[7]}")")" "${c[7]}"
                fi
                printf '\n'
            done
            printf '\n'
        fi

        if [[ ${#NO_DISPONIBLES[@]} -gt 0 ]]; then
            printf '## Plugins no disponibles con el motor elegido\n\n'
            for fila_datos in "${NO_DISPONIBLES[@]}"; do
                IFS=$'\x1f' read -r -a c <<<"${fila_datos}"
                printf -- '- %s (%s): %s\n' "${c[0]}" "${c[1]}" "${c[2]}"
            done
            printf '\n'
        fi

        if [[ ${#AVISOS[@]} -gt 0 ]]; then
            printf '## Avisos\n\n'
            for aviso in "${AVISOS[@]}"; do
                printf -- '- %s\n' "${aviso}"
            done
            printf '\n'
        fi

        printf '## Artefactos generados\n\n'
        printf -- '- Resultados: `resultados/<categoría>/<plugin>.<motor>.<formato>`\n'
        printf -- '- Log completo: `logs/voldump.log`\n'
        printf -- '- Errores de cada plugin: `logs/errores/`\n'
        printf -- '- Resumen: `resumen.txt`\n'
        if [[ -n "${HASH_SHA_ANTES}" ]]; then
            printf -- '- Hashes verificables con `sha256sum -c hashes.sha256`\n'
        fi
        if [[ -n "${ACQUIRED_FILE}" ]]; then
            printf -- '- Memoria adquirida con AVML: `%s`\n' "${ACQUIRED_FILE#"${EVIDENCE_DIR}/"}"
        fi
    } >"${EVIDENCE_DIR}/reporte.md"
}

generar_resumen() {
    local estado="$1" fila_datos
    local -a c=()
    {
        printf '%s %s\n' "${APP_NAME}" "${APP_VERSION}"
        printf 'Estado: %s\n' "$(estado_final_texto "${estado}")"
        printf 'Inicio: %s\n' "${START_HUMAN}"
        printf 'Duración: %s\n' "$(fmt_duracion $((END_EPOCH - START_EPOCH)))"
        printf 'Objetivo: %s\n' "${TARGET_LABEL:-No definido}"
        printf 'Sistema operativo: %s\n' "$(nombre_so "${DETECTED_OS}")"
        printf 'Motor: %s\n' "$(describir_motor)"
        if [[ -n "${VOL2_PROFILE}" ]]; then
            printf 'Perfil de Volatility 2: %s\n' "${VOL2_PROFILE}"
        fi
        if [[ -n "${HASH_SHA_ANTES}" ]]; then
            printf 'SHA-256: %s (%s)\n' "${HASH_SHA_ANTES}" "${HASH_ESTADO:-no verificado}"
        fi
        printf 'Plugins con resultado: %s de %s\n' "${ENTRY_OK}" "${#PLAN[@]}"
        printf 'Ejecuciones: %s (correctas: %s, con errores: %s)\n' "${RUN_TOTAL}" "${RUN_OK}" "${RUN_FAIL}"
        if [[ ${#FALLOS[@]} -gt 0 ]]; then
            printf 'Ejecuciones con errores:\n'
            for fila_datos in "${FALLOS[@]}"; do
                IFS=$'\x1f' read -r -a c <<<"${fila_datos}"
                printf ' - %s (%s, %s)\n' "${c[3]}" "$(nombre_motor "${c[2]}")" "${c[4]}"
            done
        fi
        printf 'Reporte: %s\n' "${EVIDENCE_DIR}/reporte.md"
        printf 'Log: %s\n' "${LOG_FILE}"
    } >"${EVIDENCE_DIR}/resumen.txt"
}

finalizar_analisis() {
    local estado="$1"
    if [[ "${ANALYSIS_ACTIVE}" != true ]]; then
        return 0
    fi
    ANALYSIS_ACTIVE=false
    END_EPOCH=$(date +%s)
    recopilar_resultados
    generar_avisos
    generar_resumen "${estado}"
    generar_reporte "${estado}"
    log_info "Resumen: ${EVIDENCE_DIR}/resumen.txt"
    log_info "Reporte: ${EVIDENCE_DIR}/reporte.md"
    restaurar_propietario
    LOG_FILE="${SESSION_LOG}"
}

# ---------------------------------------------------------------------------
# Flujos de análisis
# ---------------------------------------------------------------------------

validar_volcado() {
    local ruta="$1"
    if [[ ! -e "${ruta}" ]]; then
        log_error "El archivo '${ruta}' no existe."
    elif [[ ! -f "${ruta}" ]]; then
        log_error "'${ruta}' no es un archivo regular."
    elif [[ ! -r "${ruta}" ]]; then
        log_error "No hay permisos de lectura sobre '${ruta}'."
    elif [[ ! -s "${ruta}" ]]; then
        log_error "El archivo '${ruta}' está vacío."
    else
        return 0
    fi
    return 1
}

# procesar_objetivo TIPO RUTA [SO]: TIPO es volcado, adquisicion o vivo.
procesar_objetivo() {
    local tipo="$1" ruta="$2" so="${3:-${OPT_OS}}"
    TARGET_KIND="${tipo}"
    TARGET_PATH="${ruta}"
    case "${tipo}" in
        vivo) TARGET_LABEL="Memoria en vivo de $(uname -n) (/proc/kcore)" ;;
        adquisicion) TARGET_LABEL="Memoria de $(uname -n) adquirida con AVML: ${ruta}" ;;
        *) TARGET_LABEL="Volcado: ${ruta}" ;;
    esac
    log_info "Objetivo: ${TARGET_LABEL}"

    if [[ "${tipo}" != vivo ]]; then
        TARGET_SIZE=$(stat -c %s -- "${ruta}" 2>/dev/null || true)
        calcular_hashes_iniciales
    fi

    if [[ -n "${so}" ]]; then
        DETECTED_OS="${so}"
        log_info "Sistema operativo indicado: $(nombre_so "${DETECTED_OS}")"
    elif detectar_so "${ruta}"; then
        log_ok "Sistema operativo detectado: $(nombre_so "${DETECTED_OS}")"
    elif [[ "${INTERACTIVE}" == true ]]; then
        pedir_so_manual || die "Análisis cancelado: no se pudo determinar el sistema operativo."
    else
        die "No se pudo determinar el sistema operativo del volcado. Revisa logs/errores/ o fuerza el sistema con --os."
    fi
    describir_so

    elegir_motor
    seleccionar_categorias
    planificar
    ejecutar_plan
    if [[ "${tipo}" != vivo ]]; then
        verificar_integridad
    fi
    finalizar_analisis completado

    if (( ENTRY_FAIL > 0 )); then
        log_warn "Análisis terminado: ${ENTRY_OK} plugin(s) con resultado y ${ENTRY_FAIL} sin resultado. Resultados en ${EVIDENCE_DIR}"
        FINAL_EXIT="${EXIT_PARTIAL}"
    else
        log_ok "Análisis terminado sin errores. Resultados en ${EVIDENCE_DIR}"
    fi
}

analizar_volcado() {
    local ruta="$1"
    validar_volcado "${ruta}" || exit "${EXIT_FATAL}"
    iniciar_analisis
    procesar_objetivo volcado "${ruta}"
}

adquirir_con_avml() {
    local destino mem_kb libre_kb
    destino="${EVIDENCE_DIR}/adquisicion/memoria_$(uname -n)_$(date +%Y%m%d_%H%M%S).lime"
    mkdir -p -- "${EVIDENCE_DIR}/adquisicion"
    mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null) || mem_kb=""
    libre_kb=$(df -Pk -- "${EVIDENCE_DIR}" 2>/dev/null | awk 'NR == 2 {print $4}') || libre_kb=""
    if [[ "${mem_kb}" =~ ^[0-9]+$ && "${libre_kb}" =~ ^[0-9]+$ ]] && (( libre_kb < mem_kb )); then
        log_warn "Espacio libre ($(fmt_tamano $((libre_kb * 1024)))) inferior a la RAM del equipo ($(fmt_tamano $((mem_kb * 1024))))."
        confirmar "¿Continuar de todos modos?" n || return 1
    fi
    log_info "Adquiriendo la memoria con AVML en ${destino}..."
    if ! avml "${destino}"; then
        log_error "AVML no pudo adquirir la memoria."
        return 1
    fi
    ACQUIRED_FILE="${destino}"
    log_ok "Memoria adquirida: $(fmt_tamano "$(stat -c %s -- "${destino}")")."
}

comprobar_requisitos_vivo() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "El análisis en vivo necesita permisos de root. Ejecuta: sudo $0 --live"
        return 1
    fi
    if [[ "${OPT_ACQUIRE}" == true ]] && ! command -v avml >/dev/null 2>&1; then
        log_error "--acquire necesita AVML. Descárgalo de https://github.com/microsoft/avml/releases y colócalo en el PATH."
        return 1
    fi
    if ! command -v avml >/dev/null 2>&1 && [[ ! -r /proc/kcore ]]; then
        log_error "No se puede leer /proc/kcore y AVML no está instalado. Comprueba la configuración del kernel o instala AVML."
        return 1
    fi
    return 0
}

analizar_memoria_en_vivo() {
    local usar_avml=false
    comprobar_requisitos_vivo || exit "${EXIT_FATAL}"
    if command -v avml >/dev/null 2>&1; then
        if [[ "${OPT_ACQUIRE}" == true ]]; then
            usar_avml=true
        elif [[ "${INTERACTIVE}" == true ]] && confirmar "AVML está instalado. ¿Adquirir primero la memoria en un fichero (recomendado)?" s; then
            usar_avml=true
        fi
    fi
    if [[ "${usar_avml}" == false && ! -r /proc/kcore ]]; then
        die "No se puede leer /proc/kcore. Comprueba los permisos o la configuración del kernel."
    fi

    iniciar_analisis
    if [[ "${usar_avml}" == true ]]; then
        adquirir_con_avml || die "No se pudo adquirir la memoria con AVML."
        procesar_objetivo adquisicion "${ACQUIRED_FILE}" linux
        return 0
    fi

    if grep -qsE '\[(integrity|confidentiality)\]' /sys/kernel/security/lockdown; then
        log_warn "El kernel está en modo lockdown: /proc/kcore puede estar restringido y los plugins fallarán."
    fi
    log_warn "El análisis sobre /proc/kcore depende de los símbolos del kernel en ejecución; algunos plugins pueden fallar."
    procesar_objetivo vivo /proc/kcore linux
}

pedir_ruta_volcado() {
    local entrada ruta
    while true; do
        preguntar entrada "Ruta del volcado de memoria (vacío para volver): "
        if [[ -z "${entrada}" ]]; then
            return 1
        fi
        ruta=$(normalizar_ruta "${entrada}")
        if validar_volcado "${ruta}"; then
            RUTA_ELEGIDA="${ruta}"
            return 0
        fi
    done
}

menu_principal() {
    local opcion
    while true; do
        printf '\n%s¿Qué quieres hacer?%s\n' "${BLUE}" "${NC}"
        printf '  1. Analizar un volcado de memoria\n'
        printf '  2. Analizar la memoria de este equipo (Linux en ejecución)\n'
        printf '  3. Ver el catálogo de plugins\n'
        printf '  4. Salir\n'
        preguntar opcion "Opción: "
        case "${opcion}" in
            1)
                if pedir_ruta_volcado; then
                    analizar_volcado "${RUTA_ELEGIDA}"
                    confirmar "¿Quieres realizar otro análisis?" n || break
                fi
                ;;
            2)
                if comprobar_requisitos_vivo; then
                    analizar_memoria_en_vivo
                    confirmar "¿Quieres realizar otro análisis?" n || break
                fi
                ;;
            3) mostrar_catalogo ;;
            4|q|Q|salir) break ;;
            *) log_warn "Opción no válida: ${opcion}" ;;
        esac
    done
    log_info "Saliendo de ${APP_NAME}."
}

# ---------------------------------------------------------------------------
# Señales y salida
# ---------------------------------------------------------------------------

# shellcheck disable=SC2317,SC2329  # manejador de trap
on_interrupt() {
    INTERRUPTED=true
    printf '\n' >&2
    log_warn "Ejecución interrumpida por el usuario."
    detener_trabajos
    exit "${EXIT_INTERRUPTED}"
}

# shellcheck disable=SC2317,SC2329  # manejador de trap
on_exit() {
    local rc=$?
    set +o errexit
    trap - EXIT INT TERM
    if [[ "${ANALYSIS_ACTIVE}" == true ]]; then
        if [[ "${INTERRUPTED}" == true ]]; then
            finalizar_analisis interrumpido
        else
            finalizar_analisis error
        fi
    fi
    if [[ -n "${RUN_TMP}" && -d "${RUN_TMP}" ]]; then
        rm -rf -- "${RUN_TMP}"
    fi
    exit "${rc}"
}

# ---------------------------------------------------------------------------
# Inicio
# ---------------------------------------------------------------------------

main() {
    parse_args "$@"
    setup_colors
    cargar_catalogo

    if [[ "${OPT_LIST}" == true ]]; then
        mostrar_catalogo
        exit 0
    fi

    check_runtime
    RUN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/voldump.XXXXXX")
    SESSION_LOG="${RUN_TMP}/sesion.log"
    : >"${SESSION_LOG}"
    LOG_FILE="${SESSION_LOG}"
    trap on_interrupt INT TERM
    trap on_exit EXIT

    print_banner
    log_info "Iniciando ${APP_NAME} ${APP_VERSION}."
    verificar_dependencias

    if [[ -n "${OPT_FILE}" ]]; then
        analizar_volcado "$(normalizar_ruta "${OPT_FILE}")"
    elif [[ "${OPT_LIVE}" == true ]]; then
        analizar_memoria_en_vivo
    else
        menu_principal
    fi
    exit "${FINAL_EXIT}"
}

main "$@"
