# Windows Startup & Background Manager

**Windows Startup & Background Manager** es una herramienta desarrollada en Python con una interfaz gráfica intuitiva (basada en Tkinter) diseñada para optimizar el rendimiento de tu PC. Permite detectar, gestionar y deshabilitar de forma segura programas de inicio y servicios en segundo plano no esenciales en sistemas operativos Windows.

## 🚀 Características Principales

- **Gestión de Programas de Inicio**: Controla las aplicaciones que se inician con Windows desde el Registro (`HKCU`, `HKLM`) y las carpetas de inicio.
- **Control de Servicios en Segundo Plano**: Lista los servicios activos del sistema y permite desactivar aquellos innecesarios (telemetría, bloatware OEM, etc.), mostrando descripciones útiles para cada uno.
- **Protección Inteligente de Windows**: Cuenta con una lista robusta de rutas, servicios y claves de registro protegidas. **Evita que deshabilites componentes críticos** (como drivers de kernel, servicios de red, seguridad, audio base, y shell), garantizando la estabilidad del sistema operativo.
- **Puntos de Restauración**: Incluye un botón para crear Puntos de Restauración del Sistema antes de realizar cualquier cambio, permitiendo revertir modificaciones si algo sale mal.
- **Monitor de RAM**: Muestra información en tiempo real sobre el uso de la Memoria RAM.
- **Elevación de Privilegios Automática**: Si no se ejecuta como administrador, el script solicita inteligentemente los permisos necesarios, ya que son requeridos para modificar servicios y el registro.
- **Historial de Cambios Seguro**: Mantiene un registro local (`services_log.json`) de todo lo que la aplicación ha desactivado, para luego poder re-habilitar únicamente lo que el usuario modificó a través de la herramienta.

## 🛠️ Requisitos

- **Sistema Operativo**: Windows 10 / Windows 11.
- **Python**: Versión 3.x instalada (necesario si se ejecuta desde el código fuente).
- **Privilegios**: Se requieren permisos de Administrador para que la herramienta pueda aplicar los cambios.

## 📥 Instalación y Uso

1. Clona o descarga este repositorio en tu computadora.
2. Puedes abrir la aplicación de dos maneras:
   - **Método recomendado**: Haz doble clic en el archivo `INICIAR_STARTUP_MANAGER.bat`.
   - **Vía consola**: Abre tu terminal como administrador y ejecuta el script de Python:
     ```bash
     python startup_manager.py
     ```
3. Explora las pestañas de **Programas de Inicio** y **Servicios en 2do Plano**.
4. ¡Asegúrate de **crear un punto de restauración** (desde el botón superior derecho) antes de realizar configuraciones profundas!

## ⚠️ Advertencia

A pesar de que la utilidad cuenta con un sólido sistema de protección de procesos del sistema, es recomendable leer las descripciones antes de desactivar cualquier servicio o programa. No nos hacemos responsables de funcionamientos inesperados si se fuerzan configuraciones avanzadas.
