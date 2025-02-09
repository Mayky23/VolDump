import os
import subprocess
import platform
import sys
from datetime import datetime

def check_python_installation():
    """Verifica si Python 2 y 3 están instalados en el sistema."""
    python2_installed = is_installed("python2", "--version")
    python3_installed = is_installed("python3", "--version")

    if not python2_installed or not python3_installed:
        print("Python 2 o Python 3 no están instalados.")
        if ask_user("¿Desea instalarlos? (s/n): "):
            install_python_versions()
        else:
            print("Python 2 y 3 son necesarios para usar esta herramienta.")
            sys.exit(1)

def is_installed(command, version_flag):
    """Comprueba si un comando está instalado ejecutándolo con un flag de versión."""
    try:
        subprocess.run([command, version_flag], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_python_versions():
    """Instala Python 2 y 3 en Linux automáticamente. En Windows, se pide instalación manual."""
    if platform.system() == "Linux":
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "python2", "python3"], check=True)
    else:
        print("Descargue e instale manualmente Python 2 y 3 desde https://www.python.org/downloads/")

def check_volatility_installation():
    """Verifica si Volatility 2 y 3 están instalados en el sistema."""
    volatility2_installed = is_installed("volatility", "-h")
    volatility3_installed = is_installed("vol.py", "-h")

    if not volatility2_installed or not volatility3_installed:
        print("Volatility 2 o Volatility 3 no están instalados.")
        if ask_user("¿Desea instalarlos? (s/n): "):
            install_volatility_versions()
        else:
            print("Volatility 2 y 3 son necesarios para usar esta herramienta.")
            sys.exit(1)

def install_volatility_versions():
    """Instala Volatility 2 y 3 en Linux automáticamente. En Windows, se pide instalación manual."""
    if platform.system() == "Linux":
        subprocess.run(["sudo", "apt-get", "install", "-y", "git", "python2", "python2-dev", "python3", "python3-pip"], check=True)
        subprocess.run(["pip3", "install", "distorm3", "yara-python", "pycrypto"], check=True)
        subprocess.run(["git", "clone", "https://github.com/volatilityfoundation/volatility.git"], check=True)
        subprocess.run(["git", "clone", "https://github.com/volatilityfoundation/volatility3.git"], check=True)
    else:
        print("Descargue e instale manualmente Volatility 2 y 3 desde:")
        print(" - Volatility 2: https://github.com/volatilityfoundation/volatility/releases")
        print(" - Volatility 3: https://github.com/volatilityfoundation/volatility3/releases")

def ask_user(prompt):
    """Pregunta al usuario y devuelve True si responde 's' (sí)."""
    return input(prompt).strip().lower() == 's'

def display_banner():
    """Muestra el banner del script."""
    banner = """
    __      __   _ _____                        
    \ \    / /  | |  __ \                       
     \ \  / /__ | | |  | |_   _ _ __ ___  _ __  
      \ \/ / _ \| | |  | | | | | '_ ` _ \| '_ \ 
       \  / (_) | | |__| | |_| | | | | | | |_) |
        \/ \___/|_|_____/ \__,_|_| |_| |_| .__/ 
                                         | |    
                                         |_|    
    """
    print(banner)

def choose_volatility_version():
    """Permite al usuario elegir la versión de Volatility."""
    while True:
        print("1. Volatility 2")
        print("2. Volatility 3")
        choice = input("Seleccione la versión de Volatility: ")
        if choice in ['1', '2']:
            return int(choice)
        print("Opción no válida, intente de nuevo.")

def choose_analysis_type():
    """Permite al usuario elegir el tipo de análisis."""
    while True:
        print("1. Analizar un volcado de memoria existente")
        print("2. Realizar un análisis en vivo del sistema actual")
        choice = input("Seleccione el tipo de análisis: ")
        if choice in ['1', '2']:
            return 'dump' if choice == '1' else 'live'
        print("Opción no válida, intente de nuevo.")

def get_memory_dump_path():
    """Solicita al usuario la ruta del volcado de memoria."""
    while True:
        path = input("Ingrese la ruta del volcado de memoria: ")
        if os.path.isfile(path):
            return path
        print("Archivo no encontrado, intente de nuevo.")

def get_evidence_path():
    """Pregunta al usuario la ruta donde desea guardar las evidencias."""
    while True:
        path = input("Ingrese la ruta donde desea guardar las evidencias: ").strip()
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        return path

def create_evidence_directories(base_path):
    """Crea la carpeta de evidencias con subcategorías."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    main_folder = os.path.join(base_path, f"Evidencias_{timestamp}")
    os.makedirs(main_folder, exist_ok=True)

    categories = ["archivos", "logs", "red", "sistema", "usuarios"]
    category_paths = {category: os.path.join(main_folder, category) for category in categories}

    for path in category_paths.values():
        os.makedirs(path, exist_ok=True)

    return category_paths

def run_volatility_commands(volatility_version, analysis_type, evidence_path, memory_dump_path=None):
    """Ejecuta los comandos de Volatility y guarda los resultados."""
    vol_cmd = "volatility" if volatility_version == 2 else "vol.py"
    
    # Todos los comandos que mencionaste
    commands = {
        'Información General': [
            "imageinfo", "kdbgscan", "vaddump", "memmap", "moddump", "check"
        ],
        'Procesos y Módulos': [
            "pslist", "pstree", "psscan", "dlllist", "ldrmodules", "modscan",
            "cmdline", "handles", "thrdscan"
        ],
        'Archivos y Registro': [
            "filescan", "dumpfiles", "hivelist", "printkey", "hashdump",
            "shimcache", "keylogger", "dirscan", "sockscan"
        ],
        'Red y Conexiones': [
            "netscan", "connections", "sockets", "sockstat"
        ],
        'Usuarios y Credenciales': [
            "getsids", "lsa_secrets", "cachedump", "logonsessions"
        ],
        'Malware y Rootkits': [
            "malfind", "apihooks", "ssdt", "idt", "driverirp", "driverscan", "scanfiles"
        ],
        'Otros Comandos Útiles': [
            "devicetree", "soscan", "timeliner", "eventdump", "pagescan", "sessions"
        ]
    }

    paths = create_evidence_directories(evidence_path)

    for category, cmds in commands.items():
        for cmd in cmds:
            output_file = os.path.join(paths[category], f"{cmd}.txt")
            with open(output_file, "w") as f:
                cmd_args = [vol_cmd, "-f", memory_dump_path, cmd] if analysis_type == 'dump' else [vol_cmd, cmd]
                subprocess.run(cmd_args, stdout=f, stderr=subprocess.PIPE, text=True)

if __name__ == "__main__":
    display_banner()
    check_python_installation()
    check_volatility_installation()
    volatility_version = choose_volatility_version()
    analysis_type = choose_analysis_type()
    evidence_path = get_evidence_path()
    memory_dump_path = get_memory_dump_path() if analysis_type == 'dump' else None
    run_volatility_commands(volatility_version, analysis_type, evidence_path, memory_dump_path)
    print("Análisis completado. Resultados guardados en la carpeta de evidencias.")
