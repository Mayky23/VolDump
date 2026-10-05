#!/usr/bin/env bash
#
# Pruebas de VolDump con Volatility 2 y 3 simulados (tests/fakes).
# Uso: bash tests/test_voldump.sh
#
# Las condiciones se pasan entre comillas simples a "comprobar ... eval" para
# evaluarlas después de cada ejecución, de ahí SC2016 y SC2034.
# shellcheck disable=SC2016,SC2034

set -o nounset
set -o pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${RAIZ}/VolDump.sh"
FAKES="${RAIZ}/tests/fakes"

TRABAJO=$(mktemp -d "${TMPDIR:-/tmp}/voldump-tests.XXXXXX")
trap 'rm -rf -- "${TRABAJO}"' EXIT

PY_DIR=$(dirname "$(command -v python3)")
BIN3="${TRABAJO}/bin3"     # solo Volatility 3
BIN32="${TRABAJO}/bin32"   # Volatility 3 y Volatility 2
mkdir -p "${BIN3}" "${BIN32}" "${TRABAJO}/home"
ln -s "${FAKES}/vol" "${BIN3}/vol"
ln -s "${FAKES}/vol" "${BIN32}/vol"
ln -s "${FAKES}/vol2" "${BIN32}/vol2"

VOLCADO="${TRABAJO}/memoria.raw"
head -c 65536 /dev/urandom >"${VOLCADO}"

PASADAS=0
FALLIDAS=0
SALIDA=""
RC=0

# ejecutar BIN [args...]: lanza VolDump en un entorno aislado.
ejecutar() {
    local bin="$1"
    shift
    : >"${TRABAJO}/fake.log"
    SALIDA=$(cd "${TRABAJO}" && env -i \
        PATH="${bin}:${PY_DIR}:/usr/bin:/bin" \
        HOME="${TRABAJO}/home" \
        TMPDIR="${TRABAJO}" \
        LANG="C.UTF-8" \
        VOLDUMP_HOME="${TRABAJO}/voldump-home" \
        FAKE_LOG="${TRABAJO}/fake.log" \
        FAKE_OS="${FAKE_OS:-windows}" \
        FAKE_WIN="${FAKE_WIN:-7}" \
        FAKE_FAIL="${FAKE_FAIL:-}" \
        FAKE_FAIL2="${FAKE_FAIL2:-}" \
        FAKE_SLEEP="${FAKE_SLEEP:-}" \
        FAKE_OLD="${FAKE_OLD:-0}" \
        bash "${SCRIPT}" --no-install --no-color "$@" 2>&1 <"${ENTRADA:-/dev/null}")
    RC=$?
}

ok() {
    PASADAS=$((PASADAS + 1))
    printf '  ok  %s\n' "$1"
}

fallo() {
    FALLIDAS=$((FALLIDAS + 1))
    printf '  FALLO  %s\n' "$1"
    printf '%s\n' "${SALIDA}" | tail -n 25 | sed 's/^/        | /'
}

comprobar() {
    local descripcion="$1"
    shift
    if "$@"; then ok "${descripcion}"; else fallo "${descripcion}"; fi
}

rc_es() { [[ "${RC}" -eq "$1" ]]; }
contiene() { [[ "${SALIDA}" == *"$1"* ]]; }
existe() { [[ -f "${TRABAJO}/$1" ]]; }
no_existe() { [[ ! -e "${TRABAJO}/$1" ]]; }
fichero_contiene() { grep -qF -- "$2" "${TRABAJO}/$1"; }
fichero_no_contiene() { ! grep -qF -- "$2" "${TRABAJO}/$1"; }
veces_en_log() { grep -c -F -- "$1" "${TRABAJO}/fake.log"; }
limpiar() { rm -rf "${TRABAJO}"/out* "${TRABAJO}"/evidencias_*; }

echo "== Argumentos"
ejecutar "${BIN3}" --help
comprobar "--help termina con 0 y muestra el uso" eval 'rc_es 0 && contiene "Uso:"'
ejecutar "${BIN3}" --version
comprobar "--version muestra 10.1" eval 'rc_es 0 && contiene "VolDump 10.1"'
ejecutar "${BIN3}" --opcion-inventada
comprobar "una opción desconocida termina con 2" rc_es 2
ejecutar "${BIN3}" -f "${VOLCADO}" --engine vol4
comprobar "un motor inválido termina con 2" rc_es 2
ejecutar "${BIN3}" -f "${VOLCADO}" --live
comprobar "-f y --live son incompatibles" rc_es 2
ejecutar "${BIN3}" --list
comprobar "--list muestra Volatility 2 y 3 y no usa linux.info" \
    eval 'rc_es 0 && contiene "windows.info" && contiene "linux_pslist" && ! contiene "linux.info "'

echo "== Volcado de Windows (solo Volatility 3)"
limpiar
ejecutar "${BIN3}" -f "${VOLCADO}" -e vol3 -o out
comprobar "termina con 0" rc_es 0
comprobar "detecta Windows" fichero_contiene out/reporte.md "| Sistema operativo | Windows |"
comprobar "windows.handles se ejecuta (categoría archivos)" existe out/resultados/archivos/handles.vol3.txt
comprobar "windows.info se reutiliza de la detección (1 sola ejecución)" eval '[[ "$(veces_en_log windows.info)" -eq 1 ]]'
comprobar "la salida de windows.info se guarda" fichero_contiene out/resultados/general/info.vol3.txt "Kernel Base"
comprobar "usa los nombres nuevos de los plugins de malware" eval '[[ "$(veces_en_log windows.malware.malfind)" -eq 1 ]]'
comprobar "llama a Volatility 3 con -q" eval '! grep -q "windows.pslist" "${TRABAJO}/fake.log" || grep -q "vol3 -q .*windows.pslist" "${TRABAJO}/fake.log"'
comprobar "no deja ficheros de error si todo va bien" eval '[[ -z "$(ls -A "${TRABAJO}/out/logs/errores")" ]]'
comprobar "el log no contiene códigos de color" eval '! grep -q $'"'"'\033'"'"' "${TRABAJO}/out/logs/voldump.log"'
comprobar "los hashes se pueden verificar con sha256sum -c" eval '(cd "${TRABAJO}/out" && sha256sum -c --status hashes.sha256)'
comprobar "el reporte confirma la integridad" fichero_contiene out/reporte.md "Resultado de la verificación: **coincide**"
comprobar "los plugins exclusivos de Volatility 2 aparecen como no disponibles" fichero_contiene out/reporte.md "iehistory (usuario)"
comprobar "timeline no se incluye en all" no_existe out/resultados/timeline
SECUENCIAL=$(find "${TRABAJO}/out/resultados" -type f | wc -l)

echo "== Volcado de Linux"
limpiar
FAKE_OS=linux ejecutar "${BIN3}" -f "${VOLCADO}" -c general,procesos -o out
comprobar "termina con 0" rc_es 0
comprobar "detecta Linux con banners.Banners" fichero_contiene out/reporte.md "| Sistema operativo | Linux |"
comprobar "no invoca linux.info (no existe en Volatility 3)" eval '[[ "$(veces_en_log linux.info)" -eq 0 ]]'
comprobar "banners.Banners se reutiliza de la detección" eval '[[ "$(veces_en_log banners.Banners)" -eq 1 ]]'
comprobar "ejecuta linux.pslist" existe out/resultados/procesos/pslist.vol3.txt
comprobar "el reporte incluye el banner del kernel" fichero_contiene out/reporte.md "Linux version 5.15.0-91-generic"

echo "== Volcado de macOS"
limpiar
FAKE_OS=mac ejecutar "${BIN3}" -f "${VOLCADO}" -c general -o out
comprobar "detecta macOS" eval 'rc_es 0 && fichero_contiene out/reporte.md "| Sistema operativo | macOS |"'

echo "== Errores y códigos de salida"
limpiar
FAKE_FAIL=windows.netscan ejecutar "${BIN3}" -f "${VOLCADO}" -c red -e vol3 -o out
comprobar "un plugin fallido termina con 3" rc_es 3
comprobar "guarda el error del plugin" existe out/logs/errores/netscan.vol3.err
comprobar "el resumen lista el plugin fallido" fichero_contiene out/resumen.txt "windows.netscan"
comprobar "el reporte sugiere revisar los símbolos" fichero_contiene out/reporte.md "símbolos PDB"
limpiar
FAKE_OS=none ejecutar "${BIN3}" -f "${VOLCADO}" -o out
comprobar "si no detecta el sistema termina con 1 y sugiere --os" eval 'rc_es 1 && contiene "--os"'
comprobar "el reporte se genera aunque falle" fichero_contiene out/reporte.md "Finalizado por un error"
limpiar
ejecutar "${BIN3}" -f "${VOLCADO}" -c inventada -o out
comprobar "una categoría inválida termina con 2" rc_es 2
limpiar
ejecutar "${BIN3}" -f "${TRABAJO}/no-existe.raw"
comprobar "un volcado inexistente termina con 1" eval 'rc_es 1 && contiene "no existe"'

echo "== Combinación con Volatility 2"
limpiar
FAKE_FAIL=windows.netscan ejecutar "${BIN32}" -f "${VOLCADO}" -c red -o out
comprobar "modo auto: termina con 0 gracias al respaldo" rc_es 0
comprobar "detecta Volatility 2" contiene "Volatility 2 2.6.1 disponible"
comprobar "deduce el perfil Win7SP1x64 de windows.info" fichero_contiene fake.log "--profile=Win7SP1x64"
comprobar "netscan se recupera con Volatility 2" existe out/resultados/red/netscan.vol2.txt
comprobar "ejecuta connscan y sockets (solo Volatility 2)" eval 'existe out/resultados/red/connscan.vol2.txt && existe out/resultados/red/sockets.vol2.txt'
comprobar "netstat sigue usando Volatility 3" existe out/resultados/red/netstat.vol3.txt
comprobar "el reporte marca el respaldo" fichero_contiene out/reporte.md "(respaldo)"
limpiar
FAKE_WIN=10 ejecutar "${BIN32}" -f "${VOLCADO}" -c general -e both -o out
comprobar "Windows 10 build 19045 usa el perfil Win10x64_19041" fichero_contiene fake.log "--profile=Win10x64_19041"
comprobar "modo both: guarda la salida de ambos motores" eval 'existe out/resultados/general/info.vol3.txt && existe out/resultados/general/info.vol2.txt'
limpiar
ejecutar "${BIN32}" -f "${VOLCADO}" -c procesos -e vol2 -o out
comprobar "modo vol2: usa solo Volatility 2" eval 'rc_es 0 && existe out/resultados/procesos/pslist.vol2.txt && no_existe out/resultados/procesos/pslist.vol3.txt'
limpiar
ejecutar "${BIN32}" -f "${VOLCADO}" -c procesos -e vol2 -p Win7SP0x64 -o out
comprobar "--profile tiene prioridad sobre la deducción" fichero_contiene fake.log "--profile=Win7SP0x64"
limpiar
ejecutar "${BIN3}" -f "${VOLCADO}" -c procesos -e vol2 -o out
comprobar "pedir vol2 sin tenerlo instalado termina con 1" eval 'rc_es 1 && contiene "Volatility 2"'
limpiar
FAKE_OS=linux ejecutar "${BIN32}" -f "${VOLCADO}" -c procesos -o out
comprobar "Linux sin perfil: Volatility 2 no se usa y se avisa" eval 'rc_es 0 && ! grep -q "^vol2 .*linux_pslist" "${TRABAJO}/fake.log" && fichero_contiene out/reporte.md "perfil propio"'

echo "== Compatibilidad entre versiones de Volatility 3"
limpiar
FAKE_OLD=1 ejecutar "${BIN3}" -f "${VOLCADO}" -c malware -e vol3 -o out
comprobar "usa windows.malfind si no existe windows.malware.malfind" \
    eval 'rc_es 0 && grep -q " windows.malfind" "${TRABAJO}/fake.log" && ! grep -q "windows.malware.malfind" "${TRABAJO}/fake.log"'

echo "== Formatos, paralelismo y tiempo máximo"
limpiar
ejecutar "${BIN3}" -f "${VOLCADO}" -c procesos -e vol3 -r json -o out
comprobar "-r json genera ficheros .json" eval 'rc_es 0 && fichero_contiene out/resultados/procesos/pslist.vol3.json "[]"'
limpiar
ejecutar "${BIN3}" -f "${VOLCADO}" -e vol3 -j 4 -o out
PARALELO=$(find "${TRABAJO}/out/resultados" -type f 2>/dev/null | wc -l)
comprobar "-j 4 termina con 0" rc_es 0
comprobar "-j 4 genera los mismos ficheros que en secuencial (${SECUENCIAL})" eval '[[ "${PARALELO}" -eq "${SECUENCIAL}" && "${SECUENCIAL}" -ge 25 ]]'
comprobar "-j 4 registra todos los plugins en el reporte" fichero_contiene out/reporte.md "Plugins con resultado: ${SECUENCIAL}"
if command -v timeout >/dev/null 2>&1; then
    limpiar
    FAKE_SLEEP=windows.pslist:5 ejecutar "${BIN3}" -f "${VOLCADO}" -c procesos -e vol3 -t 1 -o out
    comprobar "--timeout corta los plugins lentos (código 3)" eval 'rc_es 3 && fichero_contiene out/reporte.md "timeout"'
fi

echo "== Modo interactivo"
limpiar
mkdir -p "${TRABAJO}/home/mis volcados"
cp "${VOLCADO}" "${TRABAJO}/home/mis volcados/equipo 1.raw"
printf '1\n%s\n6\nn\n' "'~/mis volcados/equipo 1.raw'" >"${TRABAJO}/entrada"
ENTRADA="${TRABAJO}/entrada" ejecutar "${BIN3}"
CARPETA=$(find "${TRABAJO}" -maxdepth 1 -name 'evidencias_*' -type d | head -n 1)
comprobar "acepta rutas con ~, espacios y comillas" eval 'rc_es 0 && [[ -n "${CARPETA}" ]]'
comprobar "la opción 6 (archivos) ejecuta handles y filescan" \
    eval '[[ -f "${CARPETA}/resultados/archivos/handles.vol3.txt" && -f "${CARPETA}/resultados/archivos/filescan.vol3.txt" ]]'
limpiar
printf '4\n' >"${TRABAJO}/entrada"
ENTRADA="${TRABAJO}/entrada" ejecutar "${BIN3}"
comprobar "salir desde el menú no crea carpetas de evidencias" \
    eval 'rc_es 0 && [[ -z "$(find "${TRABAJO}" -maxdepth 1 -name "evidencias_*")" ]]'
printf '' >"${TRABAJO}/entrada"
ENTRADA="${TRABAJO}/entrada" ejecutar "${BIN3}"
comprobar "sin entrada (EOF) informa y termina con 1" eval 'rc_es 1 && contiene "EOF"'

echo
printf 'Resultado: %d correctas, %d fallidas\n' "${PASADAS}" "${FALLIDAS}"
[[ "${FALLIDAS}" -eq 0 ]]
