# Changelog

## 10.1

### Nuevo
- Combinación de Volatility 3 y Volatility 2 con cuatro motores: `auto` (Volatility 2 como respaldo y para plugins exclusivos), `vol3`, `vol2` y `both`.
- Deducción automática del perfil de Volatility 2 a partir de `windows.info`, con `imageinfo` como alternativa.
- Instalación opcional de Volatility 2 (`--install-vol2`) o uso de un ejecutable propio (`--vol2`).
- Modo desatendido con opciones de línea de comandos (`-f`, `-c`, `-e`, `-o`, `-r`, `-t`, `-j`, `-s`, `-p`...).
- Soporte de volcados de macOS y detección de Linux/macOS con `banners.Banners`.
- MD5 y SHA-256 del volcado antes y después del análisis (`hashes.sha256`, `hashes.md5`).
- Reporte ampliado: versiones, perfil, analista, comando, integridad, tabla de resultados con duración, errores y avisos.
- Ejecución en paralelo (`-j`), tiempo máximo por plugin (`-t`) y salida JSON/CSV para Volatility 3.
- Adquisición de memoria con AVML en el modo en vivo (`--acquire`).
- Más plugins: red (`netstat`, `sockstat`, `connscan`, `sockets`), actividad de usuario, registro (claves `Run`, `shellbags`), persistencia, malware y línea temporal.
- Pruebas automáticas con Volatility simulado y CI con ShellCheck.

### Corregido
- El análisis de volcados se detenía tras detectar el sistema operativo: los mensajes de log se mezclaban con el resultado de la detección.
- Los volcados de Linux nunca se detectaban porque `linux.info` no existe en Volatility 3.
- La alternativa `python3 -m volatility3` no funciona; ahora se lanza `volatility3.cli` correctamente.
- La instalación con pip fallaba en distribuciones con PEP 668; ahora se usa un entorno virtual propio.
- Los mensajes de error de instalación no se mostraban por `set -e`, y el script salía en silencio al recibir EOF.
- La opción "Archivos y handles" no ejecutaba `windows.handles`.
- Se dejaban ficheros de error aunque el plugin terminara bien (progreso en stderr); ahora se usa `vol -q`.
- `windows.info` se ejecutaba dos veces; ahora se reutiliza la salida de la detección.
- Plugins renombrados en Volatility 3 (`windows.malfind`, `linux.check_syscall`, `linux.netfilter`...) se resuelven al nombre vigente.
- Ya no se exige root o sudo para analizar un volcado.
- Las opciones desconocidas terminaban con código 0.
- El reporte quedaba vacío si se interrumpía el análisis y se creaban carpetas vacías al salir.
- El log contenía códigos de color ANSI.
- Categorías de Linux solapadas y la categoría "Red" de Linux no mostraba conexiones.
- El código de salida era 0 aunque fallaran todos los plugins.
- Las rutas con `~`, espacios o comillas no se aceptaban.
- `pacman -Sy` (actualización parcial) sustituido por `pacman -S --needed`.
