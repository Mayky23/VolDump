# 🔎💾 VolDump

Este proyecto proporciona una herramienta para realizar análisis forenses de memoria utilizando **Volatility 2** y **Volatility 3**. Los comandos de Volatility están organizados en varias categorías y se pueden ejecutar en sistemas Linux y Windows para extraer información crítica de volcado de memoria.

![Pantalla principal de la herramienta](img/foto1.png)

## Funcionalidades

- **Verificación de instalación**: Comprueba si Python 2 y 3, así como Volatility 2 y 3, están instalados en el sistema.
- **Comandos de Volatility**: Ejecuta una serie de comandos de Volatility 2 y 3 para análisis forenses de memoria.
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

```bash
git clone https://github.com/Mayky23/VolDump
cd VolDump
```

```bash
python3 forensic_analysis.py
```



![Insertamos la ruta de la evidencia](img/foto2.png)

