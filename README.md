# 🔎💾 VolDump

Este proyecto proporciona una herramienta para realizar análisis forenses de memoria utilizando **Volatility 3**. Los comandos de Volatility están organizados en varias categorías y se pueden ejecutar en sistemas Linux y Windows para extraer información crítica de volcado de memoria.

![Pantalla principal de la herramienta](img/foto1.png)

## Funcionalidades

- **Verificación de instalación**: Comprueba si Python 3, así como Volatility 3, están instalados en el sistema.
- **Comandos de Volatility**: Ejecuta una serie de comandos de Volatility 3 para análisis forenses de memoria.
  - Información general
  - Procesos y módulos
  - Archivos y registros
  - Red y conexiones
  - Usuarios y credenciales
  - Malware y rootkits
  - Otros comandos útiles
- **Carpetas organizadas**: Los resultados se guardan en carpetas organizadas por categorías (archivos, logs, red, etc.).
- **Compatibilidad**: Compatible con sistemas Linux y Windows.

# Como utilizar VolDump

Clonar el repositorio
```bash
git clone https://github.com/Mayky23/VolDump
cd VolDump
```
Dar permisos de ejecución al script
```bash
sudo chmod +x VolDump.sh
```
Ejecutar el script
```bash
sudo ./VolDump.sh
```

