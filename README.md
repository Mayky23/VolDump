#🔎💾 VolDump

Este script de procesamiento automatizado está diseñado para ejecutar una serie de comandos de análisis forense de memoria utilizando la herramienta Volatility 3 (Versión 2.8.0). El script detecta automáticamente el sistema operativo del volcado de memoria (Windows o Linux) y ejecuta una serie de comandos específicos para cada plataforma. Además, guarda los resultados en archivos de texto organizados en una carpeta de salida.

![Pantalla principal de la herramienta](img/foto1.png)

# Como utilizar VolDump

⚠️ Para utilizar este script simplemente debemos hacer click derecho y ejecutarlo con permisos de administrador.

Acto seguido nos pedirá la ruta donde se almacena el archivo con las evidencias

![Insertamos la ruta de la evidencia](img/foto2.png)

Despues nos pedirá la ruta donde se guardarán las evidencias obtenidas por el sript

![Insertamos la ruta donde guardar el resultado de las evidencias obtenidas](img/foto3.png)

Ahora se instalarán todas las dependecias necesarias de manera automática

![Instalación de dependencias](img/foto4.png)

Una vez completado ese proceso se ejecutarán todos los comandos disponibles de Volatility 3

![Ejecución asutomática de comandos](img/foto5.png)
![Ejecución asutomática de comandos](img/foto6.png)

Y una vez completado el proceso por completo veremos lo siguiente: 
 
![Finalización del proceso](img/foto7.png)
