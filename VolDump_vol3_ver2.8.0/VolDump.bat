@echo off
:: Configurar el directorio de trabajo al directorio donde está el script
cd /d "%~dp0"

:: Cambiar la página de códigos a UTF-8 para evitar problemas de codificación
chcp 65001

:: Función para mostrar el banner
:mostrar_banner
cls
echo   Yb    dP  dP"Yb  88     8888b.  88   88 8b    d8 88""Yb
echo    Yb  dP  dP   Yb 88      8I  Yb 88   88 88b  d88 88__dP
echo     YbdP   Yb   dP 88  .o  8I  dY Y8   8P 88YbdP88 88"""
echo      YP     YbodP  88ood8 8888Y"  `YbodP' 88 YY 88 88
echo.
echo ---- By: MARH -------------------------------------------
echo.
echo Volatility 3 (2.8.0)
echo.

goto pedir_archivo

:: Preguntar al usuario la ruta del archivo de memoria
:pedir_archivo
set "archivo="
echo.
echo Ingrese la ruta completa del archivo de memoria (ej. practica1.raw):
echo.
set /p archivo="Ruta del archivo: "

:: Verificar si el archivo existe
if not exist "%archivo%" (
    echo El archivo especificado no existe. Intente nuevamente.
    timeout /t 2 > nul
    goto pedir_archivo
)

:: Confirmar archivo válido
echo Archivo configurado correctamente: %archivo%
timeout /t 2 > nul

:: Preguntar donde se guardarán las evidencias
:pedir_ruta_evidencias
set "ruta="
echo.
echo Donde desea guardar las evidencias?
echo.
set /p ruta="Ingrese la ruta completa para guardar las evidencias: "

:: Verificar que la ruta no esté vacía
if "%ruta%"=="" (
    echo No ha proporcionado una ruta. Por favor, inténtelo nuevamente.
    timeout /t 2 > nul
    goto pedir_ruta_evidencias
)

:: Verificar si la ruta existe
if not exist "%ruta%" (
    echo La ruta especificada no existe. Desea crearla? [S/N]
    set /p crear="Ingrese su opción: "
    if /i "%crear%"=="S" (
        mkdir "%ruta%"
        if errorlevel 1 (
            echo ERROR: No se pudo crear la ruta. Verifique permisos e intente nuevamente.
            timeout /t 2 > nul
            goto pedir_ruta_evidencias
        )
    ) else if /i "%crear%"=="N" (
        echo Proceso cancelado por el usuario.
        pause
        exit /b
    ) else (
        echo Opción no válida. Inténtelo nuevamente.
        timeout /t 2 > nul
        goto pedir_ruta_evidencias
    )
)

:: Crear una carpeta para guardar las evidencias con nombre "evidencias_fecha_hora"
for /f "tokens=1-4 delims=/- " %%a in ("%date%") do set fecha=%%d%%b%%c
for /f "tokens=1-2 delims=: " %%a in ("%time%") do set hora=%%a%%b
set "carpeta_evidencias=%ruta%\evidencias_%fecha%_%hora%"

:: Crear la carpeta
mkdir "%carpeta_evidencias%"

:: Instalar dependencias de Volatility 3 (si no están instaladas)
echo Instalando dependencias de Volatility 3...
pip3 install -r "%~dp0requirements.txt" > nul 2>&1
if errorlevel 1 (
    echo ERROR: Hubo un problema instalando las dependencias. Verifique su configuración e intente nuevamente.
    pause
    exit /b
)

:: Limpiar pantalla y mostrar el banner nuevamente
goto ejecutar_comandos

:ejecutar_comandos
:: Mostrar el banner y los mensajes de los comandos
cls
echo   Yb    dP  dP"Yb  88     8888b.  88   88 8b    d8 88""Yb
echo    Yb  dP  dP   Yb 88      8I  Yb 88   88 88b  d88 88__dP
echo     YbdP   Yb   dP 88  .o  8I  dY Y8   8P 88YbdP88 88"""
echo      YP     YbodP  88ood8 8888Y"  `YbodP' 88 YY 88 88
echo.
echo ---- By: MARH -------------------------------------------
echo.
echo Volatility 3 (2.8.0)
echo.

:: Ejecutar el comando imageinfo para detectar el sistema operativo
echo [INFO] Ejecutando el comando: imageinfo...
python "%~dp0vol.py" -f "%archivo%" windows.info > "%carpeta_evidencias%\imageinfo.txt"

:: Comprobar si es un sistema Windows o Linux basándose en la salida
findstr /i "windows" "%carpeta_evidencias%\imageinfo.txt" > nul
if %errorlevel%==0 (
    set "sistema=windows"
) else (
    set "sistema=linux"
)

:: Mostrar sistema detectado
echo.
echo [INFO] Sistema %sistema% detectado. Ejecutando comandos...

:: Ejecutar todos los comandos según el sistema operativo detectado
if /i "%sistema%"=="windows" (
    call :ejecutar_comando "imageinfo" "windows.info"
    timeout /t 2 > nul
    call :ejecutar_comando "pslist" "windows.pslist"
    timeout /t 2 > nul
    call :ejecutar_comando "netscan" "windows.netscan"
    timeout /t 2 > nul
    call :ejecutar_comando "filescan" "windows.filescan"
    timeout /t 2 > nul
    call :ejecutar_comando "malfind" "windows.malfind"
    timeout /t 2 > nul
    call :ejecutar_comando "handles" "windows.handles"
    timeout /t 2 > nul
    call :ejecutar_comando "dlllist" "windows.dlllist"
    timeout /t 2 > nul
    call :ejecutar_comando "registry.hivescan" "windows.registry.hivescan"
    timeout /t 2 > nul
    call :ejecutar_comando "cmdline" "windows.cmdline"
    timeout /t 2 > nul
    call :ejecutar_comando "netstat" "windows.netstat"
    timeout /t 2 > nul
) else if /i "%sistema%"=="linux" (
    call :ejecutar_comando "pslist" "linux.pslist"
    timeout /t 2 > nul
    call :ejecutar_comando "netscan" "linux.netscan"
    timeout /t 2 > nul
    call :ejecutar_comando "malfind" "linux.malfind"
    timeout /t 2 > nul
    call :ejecutar_comando "filescan" "linux.filescan"
    timeout /t 2 > nul
    call :ejecutar_comando "lsmod" "linux.lsmod"
    timeout /t 2 > nul
    call :ejecutar_comando "psscan" "linux.psscan"
    timeout /t 2 > nul
)

:: Terminar el análisis
echo.
echo *************************************
echo **      Análisis completado.       **
echo *************************************
echo.
echo Todos los resultados se han guardado en la carpeta: %carpeta_evidencias%
pause
exit /b

:: Función para ejecutar un comando y mostrar [INFO] antes de la ejecución
:ejecutar_comando
set "descripcion=%~1"
set "comando=%~2"

:: Mostrar el mensaje de ejecución
echo.
echo [INFO] Ejecutando el comando: %descripcion%...

:: Ejecutar el comando de Volatility 3 y guardar los resultados
python "%~dp0vol.py" -f "%archivo%" %comando% > "%carpeta_evidencias%\%comando%.txt" 2>&1

:: Mensaje de finalización
echo Comando ejecutado. Los resultados se guardaron en: %carpeta_evidencias%\%comando%.txt
