# VolDump

VolDump es un frontend en Bash para automatizar análisis forenses de memoria combinando **Volatility 3** y **Volatility 2**. Se ejecuta en **Linux**, prepara el entorno si faltan dependencias y lanza una batería de plugins sobre volcados de memoria de **Windows, Linux o macOS**, dejando las evidencias organizadas junto con un reporte y los hashes del volcado.

## Qué hace

- Usa **Volatility 3** como motor principal y **Volatility 2** como complemento:
  - si un plugin de Volatility 3 falla, repite el análisis con su equivalente de Volatility 2;
  - ejecuta plugins que solo existen en Volatility 2 (`connscan`, `sockets`, `shellbags`, `iehistory`...);
  - permite usar un único motor o ambos a la vez para contrastar resultados.
- Detecta automáticamente si el volcado es de Windows, Linux o macOS.
- Deduce el **perfil de Volatility 2** a partir de `windows.info` (o de `imageinfo` si hace falta).
- Funciona como asistente interactivo o de forma desatendida con opciones de línea de comandos.
- Calcula **MD5 y SHA-256** del volcado antes y después del análisis para la cadena de custodia.
- Organiza la salida por categorías y genera `reporte.md`, `resumen.txt`, log y errores por plugin.
- Instala Volatility 3 en un **entorno virtual propio** si no está disponible (compatible con PEP 668).
- Permite analizar la memoria del propio equipo (Linux), adquiriéndola con AVML o leyendo `/proc/kcore`.

## Requisitos

- Linux con Bash 4.4 o superior
- Python 3.8 o superior
- Volatility 3 (se instala automáticamente si falta)
- Opcional: Volatility 2 (`vol.py` con Python 2.7 o el binario standalone)
- Opcional: `sudo` o root, solo para instalar paquetes del sistema o analizar la memoria en vivo
- Opcional: [AVML](https://github.com/microsoft/avml) para adquirir la memoria del equipo

Gestores de paquetes soportados para instalar dependencias del sistema: `apt-get`, `dnf`, `microdnf`, `yum`, `zypper`, `pacman` y `apk`.

## Instalación

```bash
git clone https://github.com/Mayky23/VolDump.git
cd VolDump
chmod +x VolDump.sh
```

La primera vez, si Volatility 3 no está instalado, VolDump lo instala en `~/.local/share/voldump/venv3` (se puede cambiar con la variable `VOLDUMP_HOME`). No modifica el Python del sistema.

### Volatility 2 (opcional)

VolDump busca Volatility 2 en el `PATH` (`vol.py`, `vol2`, `volatility2`, `volatility`) y en `~/.local/share/voldump/volatility2`. Hay tres formas de añadirlo:

- `./VolDump.sh --install-vol2`: lo descarga del repositorio oficial y lo ejecuta con Python 2.7. Muchas distribuciones modernas ya no incluyen Python 2.
- `./VolDump.sh --vol2 /ruta/volatility_2.6_lin64_standalone`: usa el binario standalone publicado por la Volatility Foundation, que no necesita Python 2.
- Variable de entorno `VOLDUMP_VOL2=/ruta/a/vol.py`.

Si Volatility 2 no está disponible, VolDump funciona igualmente solo con Volatility 3.

## Uso

### Asistente interactivo

```bash
./VolDump.sh
```

1. Comprueba las dependencias.
2. Pregunta si quieres analizar un volcado o la memoria del equipo.
3. Calcula los hashes del volcado y detecta el sistema operativo.
4. Si Volatility 2 está disponible, te deja elegir el motor.
5. Muestra las categorías disponibles; puedes escribir números o nombres separados por comas (`1,2,5` o `procesos,red`).
6. Ejecuta los plugins y genera el reporte. Al terminar puedes lanzar otro análisis.

Las rutas admiten `~`, espacios y comillas (por ejemplo, al arrastrar el fichero a la terminal).

### Modo desatendido

```bash
# Todas las categorías (salvo la línea temporal) con el motor automático
./VolDump.sh -f /casos/equipo1.raw

# Solo procesos y red, ambos motores, salida JSON de Volatility 3 y 4 plugins en paralelo
./VolDump.sh -f equipo1.raw -c procesos,red -e both -r json -j 4 -o caso_001

# Volcado de Linux con símbolos ISF propios y un límite de 10 minutos por plugin
./VolDump.sh -f servidor.lime -s ~/simbolos -t 600

# Volatility 2 con un perfil concreto
./VolDump.sh -f xp.raw -e vol2 -p WinXPSP3x86

# Memoria del propio equipo adquirida con AVML
sudo ./VolDump.sh --live --acquire
```

### Opciones

| Opción | Descripción |
|---|---|
| `-f, --file RUTA` | Volcado de memoria a analizar |
| `--live` | Analiza la memoria del equipo en ejecución (Linux, root) |
| `--acquire` | Con `--live`, adquiere antes la memoria con AVML (recomendado) |
| `-c, --categories LISTA` | Categorías separadas por comas (por defecto `all`) |
| `--os SO` | Fuerza el sistema: `windows`, `linux` o `mac` |
| `-e, --engine MOTOR` | `auto` (defecto), `vol3`, `vol2` o `both` |
| `-p, --profile PERFIL` | Perfil de Volatility 2 (en Windows se deduce si no se indica) |
| `--vol2-plugins DIR` | Carpeta con plugins o perfiles propios de Volatility 2 |
| `-s, --symbols DIR` | Carpeta de símbolos ISF para Volatility 3 |
| `--offline` | Volatility 3 no descarga símbolos de Internet |
| `-r, --format FORMATO` | Salida de Volatility 3: `text`, `json` o `csv` |
| `-t, --timeout SEG` | Tiempo máximo por plugin (0 = sin límite) |
| `-j, --jobs N` | Plugins en paralelo |
| `-o, --output DIR` | Directorio de evidencias |
| `--no-hash` | No calcula los hashes del volcado |
| `--vol3 RUTA` / `--vol2 RUTA` | Ejecutables de Volatility que se deben usar |
| `--install-vol2` | Instala Volatility 2 si no está disponible |
| `--no-install` | No instala nada automáticamente |
| `--list` | Muestra el catálogo de plugins |
| `-y, --yes` | Acepta automáticamente las confirmaciones |
| `--no-color` | Desactiva los colores (también con `NO_COLOR`) |

### Motores

| Motor | Comportamiento |
|---|---|
| `auto` | Volatility 3 para cada plugin; si falla o solo existe en Volatility 2, se usa Volatility 2 |
| `vol3` | Solo Volatility 3 |
| `vol2` | Solo Volatility 2 (necesita perfil) |
| `both` | Ejecuta los dos motores y guarda ambas salidas para contrastarlas |

Volatility 2 necesita un perfil. En Windows VolDump lo deduce de `windows.info` (versión, service pack, arquitectura y build) eligiendo el perfil instalado más cercano; si no puede, usa `imageinfo`. En Linux y macOS hay que indicar un perfil propio con `--profile` y `--vol2-plugins`.

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Análisis completado sin errores |
| 1 | Error (dependencias, volcado inválido, sistema no detectado...) |
| 2 | Uso incorrecto de las opciones |
| 3 | Análisis completado, pero algún plugin no dio resultado |
| 130 | Interrumpido por el usuario |

## Categorías y plugins

`./VolDump.sh --list` muestra el catálogo completo con el plugin de cada motor.

| Categoría | Windows | Linux | macOS |
|---|---|---|---|
| `general` | `windows.info` / `imageinfo` | `banners`, `linux.boottime` | `banners` |
| `procesos` | `pslist`, `psscan`, `pstree`, `cmdline`, `envars`, `getsids`, `privileges` | `pslist`, `psscan`, `pstree`, `psaux`, `envars` | `pslist`, `pstree`, `psaux` |
| `usuario` | `cmdscan`, `consoles`, `userassist`, `shimcache`, `amcache`, `iehistory` | `bash` | `bash` |
| `modulos` | `dlllist`, `modules`, `modscan`, `driverscan` | `lsmod` | `lsmod` |
| `red` | `netscan`, `netstat`, `connscan`, `sockets` | `sockstat`, `ip.Addr` | `netstat`, `ifconfig` |
| `archivos` | `filescan`, `handles`, `mutantscan` | `lsof` | `lsof`, `list_files` |
| `registro` | `hivelist`, claves `Run` (HKLM y HKCU), `shellbags` | | |
| `persistencia` | `svcscan`, `scheduled_tasks` | | |
| `sistema` | | `mountinfo`, `kmsg` | `mount`, `dmesg` |
| `malware` | `malfind`, `psxview`, `ldrmodules`, `hollowprocesses`, `ssdt`, `callbacks` | `check_syscall`, `check_modules`, `hidden_modules`, `malfind`, `check_creds`, `check_afinfo`, `tty_check`, `netfilter`, `ebpf` | `malfind`, `check_syscall`, `check_sysctl`, `check_trap_table`, `socket_filters` |
| `timeline` | `timeliner` | `timeliner` | `timeliner` |

`all` incluye todas las categorías salvo `timeline`, que es muy lenta; pídela de forma explícita (`-c all,timeline`).

Cuando un plugin cambia de nombre entre versiones de Volatility 3 (por ejemplo `windows.malfind` → `windows.malware.malfind`), VolDump usa el nombre que exista en la versión instalada.

## Estructura de salida

```text
evidencias_20261005_163000/
├── adquisicion/          # solo con --acquire
├── hashes.md5
├── hashes.sha256         # verificable con: sha256sum -c hashes.sha256
├── logs/
│   ├── errores/          # stderr de los plugins que fallan
│   └── voldump.log
├── resultados/
│   ├── general/
│   │   ├── info.vol3.txt
│   │   └── info.vol2.txt
│   ├── procesos/
│   ├── red/
│   └── ...
├── reporte.md
└── resumen.txt
```

Cada resultado se llama `<plugin>.<motor>.<formato>`. El reporte incluye la información del caso (objetivo, tamaño, sistema detectado, versiones de Volatility, perfil, analista y comando), la verificación de integridad, una tabla con el estado y la duración de cada plugin, los errores con su causa y avisos con posibles soluciones (por ejemplo, símbolos que faltan).

## Pruebas

```bash
bash tests/test_voldump.sh
```

Las pruebas usan versiones simuladas de Volatility 2 y 3 (`tests/fakes/`), así que no necesitan volcados reales. GitHub Actions ejecuta ShellCheck y las pruebas en cada push.

## Limitaciones

- No reemplaza el análisis manual ni la interpretación forense de los resultados.
- Volatility 3 necesita símbolos: en Windows los descarga de Microsoft la primera vez (requiere Internet); en Linux y macOS hay que generarlos con [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) para el kernel exacto y pasarlos con `-s`.
- Volatility 2 está descontinuado y requiere Python 2.7 o el binario standalone; para Linux y macOS necesita perfiles propios.
- El análisis directo de `/proc/kcore` depende mucho de la configuración del kernel (lockdown, símbolos). Para resultados reproducibles es mejor adquirir la memoria con AVML o LiME.
