"""
=============================================================
  Windows Startup & Background Manager
  Autor: GitHub Copilot  |  Para: Niko Vanetti
  Detecta y permite deshabilitar programas de inicio y
  servicios en segundo plano NO esenciales del sistema.
=============================================================
"""

import ctypes
import sys
import os
import re
import json
import winreg
import subprocess
import threading
import struct
import shutil
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont

# Patrón de servicios por-usuario: nombre + sufijo hexadecimal dinámico, ej. CDPUserSvc_b879b
_PER_USER_SVC_RE = re.compile(r'^(.+)_[0-9a-fA-F]{4,8}$')

# ──────────────────────────────────────────────────────────────
#  SOLICITAR PRIVILEGIOS DE ADMINISTRADOR
# ──────────────────────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate():
    """Re-lanzar el script con privilegios de administrador."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}"', None, 1
    )
    sys.exit()

# ──────────────────────────────────────────────────────────────
#  LISTAS DE PROTECCIÓN  (componentes críticos de Windows)
# ──────────────────────────────────────────────────────────────

# Palabras clave en el PATH del ejecutable → protegido automáticamente
# Aplica tanto a programas de inicio como a servicios (detección dinámica).
# Así funciona en CUALQUIER máquina sin importar el nombre del servicio.
PROTECTED_PATH_KEYWORDS = [
    r"\windows\system32",
    r"\windows\syswow64",
    r"\windows\explorer",
    r"\windows\system",
    # Drivers de kernel — NUNCA tocar, son el núcleo del SO
    r"\system32\drivers",   # todos los .sys de kernel (ya cubiertos por system32, doble seguridad)
    r"\syswow64\drivers",
    # Seguridad
    r"\programdata\microsoft\windows defender",
    r"\windows security",
    r"\windefend",
    r"\mrt.exe",
    r"\securityhealthservice",
    # Shell / UI
    r"\ctfmon",          # teclado / IME — NO tocar
    r"\sihost",          # shell infrastructure
    r"\runtimebroker",
    r"\startmenuexperiencehost",
    r"\shellexperiencehost",
    r"\searchhost",
    r"\dwm.exe",         # desktop window manager
    r"\fontdrvhost",
    # Proceso core
    r"\lsass",
    r"\csrss",
    r"\wininit",
    r"\winlogon",
    r"\services",
    # NOTA: svchost.exe NO se incluye aquí porque se usa también para
    # verificar servicios, y casi todos (incluyendo los de terceros)
    # corren dentro de svchost, lo que haría que todo quedara bloqueado.
]

# Nombres de entrada de registro concretos de Windows → protegidos
PROTECTED_REG_NAMES = {
    "SecurityHealth",
    "Windows Security Notification",
    "Windows Defender",
    "OneDrive",         # se puede debatir, pero lo protegemos por ser MS
    "MicrosoftEdgeAutoLaunch",
    "CTF Loader",
    "ctfmon",
    "IAStoricon",       # caso raro pero Intel RST
}

# Servicios que NUNCA deben tocarse (nombre corto del servicio)
PROTECTED_SERVICES = {
    # Core del SO
    "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "lsass",
    "wininit", "csrss", "winlogon", "smss",
    # Audio
    "AudioSrv", "AudioEndpointBuilder",
    # Red / seguridad
    "Dhcp", "Dnscache", "NlaSvc", "netprofm", "LanmanWorkstation",
    "LanmanServer", "Netlogon", "CryptSvc", "KeyIso", "VaultSvc",
    "NgcSvc", "NgcCtnrSvc", "WinDefend", "SecurityHealthService",
    "mpssvc", "MpsSvc", "BFE", "WdNisSvc", "WdNisDrv",
    "wscsvc",  # Security Center
    # Windows Update
    "wuauserv", "UsoSvc", "WaaSMedicSvc", "bits",
    # Gráficos / pantalla
    "DWM", "DxgKrnl", "GraphicsPerfSvc",
    # Sistema de archivos
    "Ntfs", "FltMgr", "volsnap", "disk", "partmgr",
    # Registro y eventos
    "EventLog", "EventSystem", "SENS",
    # Energía
    "Power", "UxSms", "hidserv",
    # Plugin WMI / gestión
    "Winmgmt", "WMI", "Schedule", "ProfSvc",
    # Plug and Play
    "PlugPlay", "pnpclean",
    # Impresión y fuentes
    "FontCache", "gpsvc",
    # Accesibilidad / IME
    "TabletInputService", "TextInputManagementService",
    # Virtualización (no romper Hyper-V si está activo)
    "vmms", "vmcompute", "HvHost",
    # Otras
    "SysMain",   # Superfetch — acelera carga de apps
    "ClipSVC",   # Windows Store apps
    "wlidsvc",   # Microsoft Account
    "LicenseManager",
    "sppsvc",    # Software Protection (activación)
    "TrustedInstaller",
    "tiledatamodelsvc",
    "CDPSvc",    # Connected Devices Platform
    "UserDataSvc",
    "WpnService",  # notificaciones push
    "TokenBroker",
    "CoreMessagingRegistrar",
    "DeviceAssociationService",
    "DispBrokerDesktopSvc",  # gestión de pantallas
    "PrintWorkflowUserSvc",
    "StateRepository",
    "AppXSvc",
    "InstallService",
    "wlpasvc",
    # Servicios con PPL (Protected Process Light) — ERROR 5 aunque seas admin
    "BrokerInfrastructure",  # Background Tasks Infrastructure
    "SystemEventsBroker",    # System Events Broker
    "NcbService",            # Network Connection Broker
    "TimeBrokerSvc",         # Time Broker
    "RmSvc",                 # Radio Management
    "WpnService",            # Windows Push Notifications
    "MDCoreSvc",             # Microsoft Defender Core
    "webthreatdefsvc",       # Web Threat Defense (Defender)
    "webthreatdefusersvc",
    "cbdhsvc",               # Clipboard User Service (template)
    "WpnUserService",        # Push Notifications User Service (template)
    "CDPUserSvc",            # Connected Devices Platform User Svc (template)
    "OneSyncSvc",            # Sync Host (template)
    "PrintWorkflowUserSvc",
    "DevicesFlowUserSvc",
    "CredentialEnrollmentManagerUserSvc",
    "PimIndexMaintenanceSvc",
    "UnistoreSvc",
    "UserDataSvc",
    "UdkUserSvc",

    # ── RED / CONECTIVIDAD ─────────────────────────────────────────────────────
    # Estos servicios son los responsables de que tengas Wi-Fi, Ethernet e Internet.
    # Deshabilitarlos dejó sin red al usuario en versiones anteriores.
    "WlanSvc",          # WLAN AutoConfig — Wi-Fi COMPLETO. Sin esto, no hay Wi-Fi.
    "WwanSvc",          # WWAN — banda ancha móvil (4G/5G vía USB o integrado)
    "Wcmsvc",           # Windows Connection Manager — decide qué red usar
    "Netman",           # Network Connections — sin este no se ven/configuran adaptadores
    "nsi",              # Network Store Interface — base de bajo nivel de toda la pila de red
    "iphlpsvc",         # IP Helper — soporte IPv6, Teredo, ISATAP, túneles
    "lmhosts",          # TCP/IP NetBIOS Helper — resolución NetBIOS en red local
    "NcaSvc",           # Network Connectivity Status — detecta si y qué acceso a Internet hay
    "NetSetupSvc",      # Network Setup Service — configuración automática de red
    "WifiCalling",      # Wi-Fi Calling — VoIP sobre Wi-Fi (operadoras)

    # ── AUTENTICACIÓN / SEGURIDAD BASE ────────────────────────────────────────
    "SamSs",            # Security Accounts Manager — gestión de cuentas locales
    "Lsa",              # Local Security Authority — NO tocar (alias de lsass)

    # ── SHELL / EXPERIENCIA DE USUARIO ───────────────────────────────────────
    # La tecla Windows y el menú Start dependen de estos procesos.
    "ShellHWDetection", # Shell Hardware Detection — eventos de autoplay USB/CD
    "UxSms",            # Desktop Window Manager Session Manager (compat. Win 8/10)

    # ── ENTRADA / TECLADO / MOUSE ─────────────────────────────────────────────
    # Sin estos servicios el teclado físico puede dejar de funcionar
    # (el usuario perdió la tecla Windows en versiones anteriores).
    "hidserv",          # Human Interface Device Access — base HID (ya protegido arriba, refuerzo)
    "TabletInputService",       # Panel de entrada — Input Method Editor (IME), ya protegido
    "TextInputManagementService",  # Text Input Management — teclado táctil / IME Win10+

    # ── ENERGÍA ───────────────────────────────────────────────────────────────
    "Power",            # Power — gestión de energía: sin esto no hay apagado correcto

    # ── BLUETOOTH ─────────────────────────────────────────────────────────────
    "BthAvctpSvc",      # Bluetooth Audio/Video — perfil A2DP
    "bthserv",          # Bluetooth Support Service — base del stack Bluetooth

    # ── CUENTAS DE USUARIO / SESIONES ─────────────────────────────────────────
    # Sin UserManager las sesiones de usuario no se inicializan correctamente,
    # algunas apps dejan de funcionar y puede romperse el inicio de sesión.
    "UserManager",      # User Manager — creación y gestión de sesiones de usuario

    # ── PERMISOS DE PRIVACIDAD (CÁMARA / MICRÓFONO / UBICACIÓN) ───────────────
    # camsvc gestiona los permisos de privacidad de Windows (Configuración → Privacidad).
    # Sin este servicio las apps no pueden solicitar acceso a cámara, micrófono ni ubicación.
    "camsvc",           # Capability Access Manager — permisos cam/mic/ubicación

    # ── ALMACENAMIENTO / USB ───────────────────────────────────────────────────
    # StorSvc gestiona la detección de unidades USB y el autoplay.
    # Sin este servicio los dispositivos de almacenamiento USB pueden no reconocerse.
    "StorSvc",          # Storage Service — detección de USB y autoplay
}

# Lookup en minúsculas para comparación sin distinción de mayúsculas
# (CIM puede devolver nombres con diferente capitalización, ej. Audiosrv vs AudioSrv)
PROTECTED_SERVICES_LOWER = {s.lower() for s in PROTECTED_SERVICES}

# Descripciones amigables para servicios comunes deshabilitables
SERVICE_DESCRIPTIONS = {
    "StiSvc":       "Windows Image Acquisition (WIA) – escáneres/cámaras",
    "WSearch":      "Windows Search – indexación de archivos (hace búsqueda más rápida, consume RAM)",
    "Fax":          "Servicio de Fax – raramente usado hoy en día",
    "TapiSrv":      "Telefonía TAPI – necesario solo si usas módems telefónicos",
    "RemoteRegistry":"Registro Remoto – permite acceso remoto al registro",
    "WerSvc":       "Informe de errores de Windows – envía datos a Microsoft",
    "DiagTrack":    "Connected User Experiences / Telemetría – datos de uso a Microsoft",
    "dmwappushservice": "WAP Push – parte de la telemetría de Microsoft",
    "RetailDemo":   "Modo demo de tienda – innecesario en PC normal",
    "MapsBroker":   "Mapas sin conexión – descarga y actualiza mapas",
    "lfsvc":        "Geolocalización – servicios de ubicación",
    "XblAuthManager":"Xbox Live Auth – autenticación de Xbox Live",
    "XblGameSave":  "Xbox Live Game Save – guardado en la nube de Xbox",
    "XboxGipSvc":   "Xbox Accessories – para accesorios Xbox conectados",
    "XboxNetApiSvc":"Xbox Live Networking – red Xbox Live",
    "Spooler":      "Cola de impresión – necesario SOLO si tienes impresora",
    "PrintNotify":  "Notificaciones de impresora",
    "RemoteAccess": "Enrutamiento y acceso remoto VPN/RAS",
    "SessionEnv":   "Remote Desktop Configuration",
    "TermService":  "Remote Desktop Services – Escritorio remoto",
    "UmRdpService": "Remote Desktop Device Redirector",
    "icssvc":       "Zona compartida en móvil – hotspot desde PC",
    "SharedAccess": "Conexión compartida a Internet",
    "SCPolicySvc":  "Smart Card Removal Policy",
    "SCardSvr":     "Smart Card – lector de tarjetas inteligentes",
    "ScDeviceEnum": "Smart Card Device Enumeration",
    "WbioSrvc":     "Windows Biometric – Face ID / huella (necesario si los usas)",
    "TabletInputService": "Panel de entrada de Tablet PC",
    "Themes":       "Temas de Windows – interfaz visual (sin esto, apariencia básica)",
    "WlanSvc":      "WLAN AutoConfig – WiFi (NO deshabilitar si usas WiFi)",
    "dot3svc":      "Wired AutoConfig – 802.1x en redes cableadas corporativas",
    "BrokerInfrastructure": "Background Tasks Infrastructure Service",
    "DPS":          "Diagnostic Policy Service – diagnóstico del sistema (el solucionador de problemas de Windows deja de funcionar)",
    "WdiSystemHost":"Windows Diagnostic System Host",
    "WdiServiceHost":"Windows Diagnostic Service Host",
    # ── Drivers de audio de terceros ──────────────────────────────────────────
    "RtkAudioUniversalService": "⚠ Realtek Audio Universal – driver de audio Realtek. CUIDADO: deshabilitar puede dejar SIN AUDIO aunque AudioSrv siga activo",
    "IntelAudioService": "⚠ Intel Audio Service – driver de audio Intel SST. CUIDADO: puede dejar sin audio en equipos con audio Intel",
    "DtsApo4Service":   "DTS Audio Processing – mejoras de sonido DTS (sin esto DTS dejará de funcionar, el audio básico sigue)",
    # ── Red y optimización ────────────────────────────────────────────────────
    "DoSvc":            "Delivery Optimization – descarga de actualizaciones vía P2P entre PCs. Sin esto Windows Update sigue funcionando (solo servidor MS)",
    "DusmSvc":          "Data Usage – monitoreo de uso de datos de red por app",
    # ── Sistema Windows ───────────────────────────────────────────────────────
    "InventorySvc":     "Inventory & Compatibility – seguimiento de apps instaladas para compatibilidad",
    "TrkWks":           "Distributed Link Tracking Client – rastrea accesos directos movidos en red local. Innecesario en PC doméstica",
    "whesvc":           "Windows Hardware Error Architecture – registro de errores de hardware en el Event Log",
    # ── Drivers NVIDIA / AMD / Intel (GPU) ───────────────────────────────────
    "NVDisplay.ContainerLocalSystem": "NVIDIA Display Container – panel de control NVIDIA (G-Sync, overlay). Sin esto el panel no abre pero la imagen sigue",
    "NVDisplay.Container":           "NVIDIA Display Container – variante sin 'LocalSystem'",
    "nvagent":                       "NVIDIA Network Access Manager",
    "nvsvc":                         "NVIDIA Driver Helper – complemento del driver gráfico NVIDIA",
    "AMDRyzenMasterDriverV*":        "AMD Ryzen Master Driver – overclock/monitoreo AMD. Solo necesario si usas Ryzen Master",
    "AmdPPM":                        "AMD Processor Power Management – gestión de energía CPU AMD",
    "amdlog":                        "AMD Logging Service",
    "igccservice":                   "Intel Graphics Command Center – panel de control gráfico Intel",
    "igfxCUIService":                "Intel HD Graphics – servicio del panel de control Intel (versión antigua)",
    # ── Audio de terceros (distintos fabricantes) ─────────────────────────────
    "CxAudioSvc":                    "⚠ Conexant Audio – driver de audio Conexant/POLARIS. CUIDADO: deshabilitar puede quitar el audio",
    "CxUtilSvc":                     "⚠ Conexant Utility Service – complemento del driver Conexant",
    "SynTPEnhService":               "Synaptics Touchpad – servicio del touchpad Synaptics",
    "ETDService":                    "⚠ ELAN Touchpad Service – driver touchpad ELAN. Deshabilitar puede romper el touchpad",
    "HDAudBus":                      "Audio HD Bus – bus de audio de alta definición (driver de kernel)",
    # ── OEM: Dell ─────────────────────────────────────────────────────────────
    "DellDataVault":                 "Dell Data Vault – recolección de datos del sistema Dell",
    "DellDataVaultWizard":           "Dell Data Vault Wizard",
    "DellSupportAssistRemediation":  "Dell SupportAssist Remediation – reparación automática Dell",
    "DSAService":                    "Dell SupportAssist – diagnóstico y soporte Dell",
    "DSAUpdateService":              "Dell SupportAssist Update Service",
    "DellClientManagementService":   "Dell Client Management – gestión remota corporativa Dell",
    "DellTechHub":                   "Dell Tech Hub – centro de aplicaciones Dell",
    "DCPD":                          "Dell Command Power Manager",
    # ── OEM: HP ───────────────────────────────────────────────────────────────
    "HpHotKeyMonSvc":                "HP Hotkey Monitor – teclas de función y atajo HP",
    "HPSupportSolutionsFramework":   "HP Support Solutions Framework – diagnóstico HP",
    "hpqwmiex":                      "HP WMI Extension – telemetría HP",
    "HPNetworkCommunicator":         "HP Network Communicator",
    "hp3dwrapsvc":                   "HP 3D DriveGuard – protección HDD en portátiles HP",
    "HPDiagsCommunicator":           "HP Diagnostics Communicator",
    # ── OEM: Lenovo ───────────────────────────────────────────────────────────
    "ImControllerService":           "Lenovo Vantage Service – herramienta de soporte Lenovo",
    "LenovoFnAndFunctionKeys":       "Lenovo Fn Keys – teclas de función Lenovo",
    "LenovoVantageService":          "Lenovo Vantage – centro de soporte Lenovo",
    "LenovoSystemUpdateAddin":       "Lenovo System Update – actualizaciones de firmware/drivers Lenovo",
    # ── OEM: ASUS ─────────────────────────────────────────────────────────────
    "ArmourySocketServer":           "ASUS Armoury Crate – control LED/RGB/fans ASUS",
    "AsusUpdateCheck":               "ASUS Update Check",
    "asus_framework":                "ASUS System Optimization",
    "LightingService":               "ASUS/Acer Lighting Service – control LED RGB",
    # ── OEM: MSI ──────────────────────────────────────────────────────────────
    "MSI_Dragon_Center":             "MSI Dragon Center – control RGB/fans MSI",
    "MSICenterService":              "MSI Center Service – herramienta OEM MSI",
    # ── Software común de terceros ────────────────────────────────────────────
    "AdobeARMservice":               "Adobe Acrobat Update – actualizaciones automáticas de Adobe",
    "AdobeUpdateService":            "Adobe Update Service",
    "AGSService":                    "Adobe Genuine Software Service – verificación de licencia Adobe",
    "MozillaMaintenance":            "Mozilla Maintenance – actualizaciones de Firefox",
    "GoogleChromeElevationService":  "Chrome Elevation Service – instalador de Chrome",
    "gupdate":                       "Google Update – actualizaciones automáticas de apps Google",
    "gupdatem":                      "Google Update (manual) – actualizaciones de apps Google",
    "Corsair":                       "Corsair Service – software de periféricos Corsair (RGB/iCUE)",
    "CorsairVBusDriver":             "Corsair Virtual Bus Driver",
    "logi_lamparray_service":        "Logitech LampArray – control LED RGB de dispositivos Logitech (G-Hub)",
    "LogiRegistryService":           "Logitech Registry Service",
    "RazerCentralService":           "Razer Central – software Razer Synapse",
    "RzSdkService":                  "Razer SDK Service – Chroma RGB (Razer)",
    "SteelSeriesTrayManager":        "SteelSeries Engine – software periféricos SteelSeries",
    "PcaSvc":       "Program Compatibility Assistant – compatibilidad de apps antiguas",
    "BDESVC":       "BitLocker Drive Encryption – cifrado de disco",
    "EFS":          "Encrypting File System – cifrado de archivos NTFS",
    "CertPropSvc":  "Certificate Propagation – certificados de smart card",
    "wercplsupport":"Windows Error Reporting Panel",
    "Wecsvc":       "Windows Event Collector",
    "stisvc":       "WIA – escáner/cámara (duplicado amigable)",
}

# ──────────────────────────────────────────────────────────────
#  FUNCIONES DE UTILIDAD
# ──────────────────────────────────────────────────────────────

def is_path_protected(path: str) -> bool:
    """Devuelve True si el ejecutable pertenece a un componente del sistema."""
    if not path:
        return False
    lower = path.lower().replace("/", "\\")
    for kw in PROTECTED_PATH_KEYWORDS:
        if kw in lower:
            return True
    return False

def run_ps(command: str) -> str:
    """Ejecuta un comando PowerShell y devuelve la salida."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()

# ──────────────────────────────────────────────────────────────
#  STARTUP ITEMS  (registro + carpeta de inicio)
# ──────────────────────────────────────────────────────────────

REG_RUN_PATHS = [
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKCU"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "HKLM"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM32"),
]

APPROVED_PATHS = {
    "HKCU":   (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    "HKLM":   (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
    "HKLM32": (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
}

STARTUP_FOLDERS = [
    Path(os.environ.get("APPDATA","")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    Path(os.environ.get("PROGRAMDATA","")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
]

def _read_startup_approved(hive, subkey) -> dict:
    """Lee el estado habilitado/deshabilitado de StartupApproved."""
    states = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                    # bytes[0] == 2 → enabled, bytes[0] == 3 → disabled
                    enabled = (len(data) >= 4 and data[0] == 2)
                    states[name.lower()] = enabled
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return states

def _set_startup_approved(hive, subkey, name, enable: bool):
    """Escribe el byte de habilitado/deshabilitado en StartupApproved."""
    try:
        with winreg.OpenKey(hive, subkey, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            try:
                data, _ = winreg.QueryValueEx(k, name)
                data = bytearray(data) if data else bytearray(12)
            except OSError:
                data = bytearray(12)
            if len(data) < 12:
                data = bytearray(12)
            data[0] = 2 if enable else 3
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, bytes(data))
    except PermissionError:
        raise PermissionError(f"Sin permisos para modificar {subkey}\\{name}")

def get_startup_items():
    """Retorna lista de dicts con los programas de inicio."""
    items = []
    for (hive, path, tag) in REG_RUN_PATHS:
        approved_hive, approved_path = APPROVED_PATHS[tag]
        states = _read_startup_approved(approved_hive, approved_path)
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        i += 1
                        exe_path = value.strip('"').split('"')[0] if value.startswith('"') else value.split(" ")[0]
                        protected = (
                            is_path_protected(value) or
                            name in PROTECTED_REG_NAMES
                        )
                        enabled = states.get(name.lower(), True)  # sin entrada = habilitado
                        items.append({
                            "source":    tag,
                            "name":      name,
                            "value":     value,
                            "exe":       exe_path,
                            "enabled":   enabled,
                            "protected": protected,
                            "type":      "registry",
                            "_hive":     approved_hive,
                            "_path":     approved_path,
                        })
                    except OSError:
                        break
        except OSError:
            pass

    # Carpetas de inicio (habilitados + deshabilitados por este script)
    VALID_EXTS = {".lnk", ".url", ".bat", ".cmd", ".vbs", ".ps1", ".exe"}
    for folder in STARTUP_FOLDERS:
        if not folder.exists():
            continue
        source = "Carpeta Usuario" if "AppData" in str(folder) else "Carpeta Todos"

        def _add_folder_items(search_folder: Path, is_enabled: bool):
            """Agrega items de una carpeta de inicio al listado."""
            if not search_folder.exists():
                return
            for f in search_folder.iterdir():
                if f.suffix.lower() not in VALID_EXTS:
                    continue
                target = ""
                try:
                    ps = run_ps(f'(New-Object -ComObject WScript.Shell).CreateShortcut("{f}").TargetPath')
                    target = ps
                except Exception:
                    target = str(f)
                protected = is_path_protected(target) or is_path_protected(str(f))
                items.append({
                    "source":    source + ("" if is_enabled else " (deshabilitado)"),
                    "name":      f.stem,
                    "value":     str(f),
                    "exe":       target or str(f),
                    "enabled":   is_enabled,
                    "protected": protected,
                    "type":      "folder",
                    "_folder":   folder,
                    "_file":     f,
                })

        # Elementos activos en la carpeta de inicio
        _add_folder_items(folder, True)
        # Elementos deshabilitados (movidos por este script a __deshabilitados__)
        _add_folder_items(folder / "__deshabilitados__", False)
    return items

def toggle_startup_item(item: dict, enable: bool):
    """Habilita o deshabilita un programa de inicio."""
    if item["protected"]:
        raise ValueError("Este elemento está protegido por el sistema.")
    if item["type"] == "registry":
        _set_startup_approved(item["_hive"], item["_path"], item["name"], enable)
    elif item["type"] == "folder":
        f: Path = item["_file"]
        disabled_dir = item["_folder"] / "__deshabilitados__"
        if not enable:
            disabled_dir.mkdir(exist_ok=True)
            shutil.move(str(f), str(disabled_dir / f.name))
            item["_file"] = disabled_dir / f.name
        else:
            dest = item["_folder"] / f.name
            shutil.move(str(f), str(dest))
            item["_file"] = dest

# ──────────────────────────────────────────────────────────────
#  SERVICIOS EN SEGUNDO PLANO
# ──────────────────────────────────────────────────────────────

def get_services():
    """
    Obtiene servicios auto-start Y los deshabilitados por esta app.
    - StartMode='Auto'     → se muestran normalmente.
    - StartMode='Disabled' → solo se muestran si fueron deshabilitados por ESTA app
                             (según el log), para que sigan apareciendo y puedan
                             ser re-habilitados desde la UI en lugar de desaparecer.
    """
    # Traer Auto + Disabled en una sola consulta
    ps_cmd = (
        "Get-CimInstance -ClassName Win32_Service "
        "-Filter \"StartMode='Auto' OR StartMode='Disabled'\" "
        "| Select-Object Name,DisplayName,State,StartMode,PathName "
        "| ConvertTo-Json -Depth 1"
    )
    output = run_ps(ps_cmd)

    try:
        raw = json.loads(output)
    except Exception:
        return []

    if isinstance(raw, dict):
        raw = [raw]

    # Servicios que esta app deshabilitó (para mostrarlos aunque ahora sean Disabled)
    app_disabled_lower = {s.lower() for s in get_services_disabled_by_app()}

    state_map = {
        "Running":       "En ejecución",
        "Stopped":       "Detenido",
        "Start Pending": "Iniciando...",
        "Stop Pending":  "Deteniéndose...",
        "Paused":        "En pausa",
    }

    services = []
    for s in raw:
        name      = (s.get("Name") or "").strip()
        display   = (s.get("DisplayName") or name).strip()
        state     = (s.get("State") or "").strip()
        start_mode= (s.get("StartMode") or "").strip()
        path      = (s.get("PathName") or "").strip().strip('"')
        if not name:
            continue

        template   = _resolve_service_name(name)
        is_disabled_mode = (start_mode == "Disabled")

        # Los servicios en modo Disabled solo aparecen si los deshabilitó ESTA app
        if is_disabled_mode:
            if name.lower() not in app_disabled_lower and template.lower() not in app_disabled_lower:
                continue

        protected = (
            name.lower() in PROTECTED_SERVICES_LOWER or
            template.lower() in PROTECTED_SERVICES_LOWER
        )

        if is_disabled_mode:
            status_str = "🔴 Deshabilitado"
        else:
            status_str = state_map.get(state, state)

        running = (state == "Running")
        enabled = not is_disabled_mode

        description = SERVICE_DESCRIPTIONS.get(name, SERVICE_DESCRIPTIONS.get(template, ""))
        services.append({
            "name":        name,
            "display":     display,
            "status":      status_str,
            "running":     running,
            "delayed":     False,
            "protected":   protected,
            "description": description,
            "enabled":     enabled,
            "_path":       path,
        })
    return sorted(services, key=lambda x: (x["protected"], x["name"]))

def _resolve_service_name(name: str) -> str:
    """
    Los servicios por-usuario tienen instancias con sufijo dinámico (ej. CDPUserSvc_b879b).
    sc.exe solo acepta el nombre de la PLANTILLA (sin sufijo) para cambiar la configuración.
    Devuelve el nombre de plantilla si aplica, o el nombre original.
    """
    m = _PER_USER_SVC_RE.match(name)
    if m:
        return m.group(1)
    return name

def toggle_service(name: str, enable: bool):
    """Cambia startup type del servicio y registra el cambio en el log."""
    target = _resolve_service_name(name)
    start_val = "auto" if enable else "disabled"

    # Intentar configurar
    result = subprocess.run(
        ["sc", "config", target, f"start={start_val}"],
        capture_output=True, text=True
    )
    # Si la plantilla tampoco acepta el cambio, intentar con el nombre original
    if result.returncode != 0 and target != name:
        result = subprocess.run(
            ["sc", "config", name, f"start={start_val}"],
            capture_output=True, text=True
        )
    if result.returncode != 0:
        out = (result.stdout + result.stderr).strip()
        if "ERROR 5" in out or "Access is denied" in out.lower() or "Acceso denegado" in out.lower():
            raise RuntimeError(
                f"Acceso denegado: '{target}' es un proceso protegido por Windows (PPL).\n"
                "No se puede modificar incluso con permisos de administrador.\n"
                "El servicio será excluido automáticamente en futuras sesiones."
            )
        raise RuntimeError(out)

    # Registrar el cambio en el log de esta app
    if enable:
        record_service_enabled(target)
        subprocess.run(["sc", "start", target], capture_output=True)
    else:
        record_service_disabled(target)

# ──────────────────────────────────────────────────────────────
#  ARCHIVO DE SEGUIMIENTO DE CAMBIOS
#  Guarda qué servicios deshabilitó ESTE script para poder
#  revertir SOLO esos, nunca servicios que Windows mismo desactivó.
# ──────────────────────────────────────────────────────────────

_APP_DATA_DIR = Path(os.environ.get("APPDATA", "")) / "StartupManagerNiko"
CHANGES_LOG   = _APP_DATA_DIR / "services_log.json"

def _load_changes_log() -> dict:
    """Carga el registro de cambios hechos por esta app."""
    try:
        if CHANGES_LOG.exists():
            with open(CHANGES_LOG, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"disabled_by_app": []}

def _save_changes_log(log: dict):
    """Guarda el registro de cambios en disco."""
    try:
        _APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(CHANGES_LOG, "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def record_service_disabled(name: str):
    """Registra que esta app deshabilitó el servicio `name`."""
    log = _load_changes_log()
    if name not in log["disabled_by_app"]:
        log["disabled_by_app"].append(name)
    _save_changes_log(log)

def record_service_enabled(name: str):
    """Elimina el servicio `name` del registro de deshabilitados."""
    log = _load_changes_log()
    log["disabled_by_app"] = [s for s in log["disabled_by_app"] if s != name]
    _save_changes_log(log)

def get_services_disabled_by_app() -> list[str]:
    """Devuelve la lista de servicios que esta app deshabilitó."""
    return _load_changes_log().get("disabled_by_app", [])

# ──────────────────────────────────────────────────────────────
#  PUNTO DE RESTAURACIÓN DEL SISTEMA
# ──────────────────────────────────────────────────────────────

def create_restore_point(description: str = "Startup Manager — antes de cambios") -> bool:
    """
    Crea un Punto de Restauración del Sistema de Windows.
    Requiere que la Protección del Sistema esté habilitada en la unidad C:.
    Devuelve True si tuvo éxito.
    """
    ps_cmd = (
        "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue; "
        f"Checkpoint-Computer -Description '{description}' "
        "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0
    except Exception:
        return False

# ──────────────────────────────────────────────────────────────
#  INFORMACIÓN DE MEMORIA RAM
# ──────────────────────────────────────────────────────────────

def get_ram_info() -> dict:
    ps = run_ps(
        "Get-CimInstance Win32_OperatingSystem |"
        " Select-Object TotalVisibleMemorySize,FreePhysicalMemory |"
        " ConvertTo-Json"
    )
    import json as _json
    try:
        data = _json.loads(ps)
        total = data.get("TotalVisibleMemorySize", 0) / (1024 * 1024)   # GB
        free  = data.get("FreePhysicalMemory",     0) / (1024 * 1024)   # GB
        used  = total - free
        pct   = (used / total * 100) if total else 0
        return {"total": total, "used": used, "free": free, "pct": pct}
    except Exception:
        return {"total": 0, "used": 0, "free": 0, "pct": 0}

# ──────────────────────────────────────────────────────────────
#  GUI PRINCIPAL
# ──────────────────────────────────────────────────────────────

COLORS = {
    "bg":         "#1a1a2e",
    "panel":      "#16213e",
    "accent":     "#0f3460",
    "green":      "#4ade80",
    "red":        "#f87171",
    "yellow":     "#fbbf24",
    "orange":     "#fb923c",
    "blue":       "#60a5fa",
    "gray":       "#6b7280",
    "text":       "#f1f5f9",
    "subtext":    "#94a3b8",
    "protected":  "#334155",
    "row_even":   "#1e293b",
    "row_odd":    "#0f172a",
}

class StartupManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Windows Startup & Background Manager  —  Niko Vanetti")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=COLORS["bg"])
        self._startup_items    = []
        self._services         = []
        self._startup_iid_map  = {}   # treeview iid → startup item dict
        self._service_iid_map  = {}   # treeview iid → service dict
        self._build_ui()
        self.after(100, self._load_all)

    # ── Layout ──────────────────────────────────────────────
    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=COLORS["bg"], foreground=COLORS["text"],
                        fieldbackground=COLORS["panel"])
        style.configure("TNotebook",       background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",   background=COLORS["accent"], foreground=COLORS["text"],
                        padding=[14, 6], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["panel"])],
                  foreground=[("selected", COLORS["green"])])
        style.configure("Treeview",        background=COLORS["row_even"],
                        foreground=COLORS["text"], rowheight=26,
                        fieldbackground=COLORS["row_even"], borderwidth=0)
        style.configure("Treeview.Heading", background=COLORS["accent"],
                        foreground=COLORS["blue"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", COLORS["accent"])])
        style.configure("TScrollbar",      background=COLORS["accent"],
                        troughcolor=COLORS["bg"], borderwidth=0)
        style.configure("TFrame",          background=COLORS["bg"])
        style.configure("TLabel",          background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("TLabelframe",     background=COLORS["bg"], foreground=COLORS["blue"],
                        bordercolor=COLORS["accent"])
        style.configure("TLabelframe.Label", background=COLORS["bg"],
                        foreground=COLORS["blue"], font=("Segoe UI", 9, "bold"))

        # Header
        hdr = tk.Frame(self, bg=COLORS["accent"], height=52)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚙  Windows Startup & Background Manager",
                 bg=COLORS["accent"], fg=COLORS["blue"],
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=18, pady=10)
        self._ram_lbl = tk.Label(hdr, text="RAM: calculando...",
                                 bg=COLORS["accent"], fg=COLORS["yellow"],
                                 font=("Segoe UI", 10))
        self._ram_lbl.pack(side="right", padx=18)

        # Admin badge
        if is_admin():
            badge_txt, badge_fg = "● Admin", COLORS["green"]
        else:
            badge_txt, badge_fg = "● Sin admin (funciones limitadas)", COLORS["orange"]
        tk.Label(hdr, text=badge_txt, bg=COLORS["accent"], fg=badge_fg,
                 font=("Segoe UI", 9)).pack(side="right", padx=10)

        # Notebook
        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=8, pady=6)

        self._tab_startup  = ttk.Frame(self._nb)
        self._tab_services = ttk.Frame(self._nb)
        self._tab_info     = ttk.Frame(self._nb)
        self._nb.add(self._tab_startup,  text="🚀  Programas de Inicio")
        self._nb.add(self._tab_services, text="⚙  Servicios en Segundo Plano")
        self._nb.add(self._tab_info,     text="ℹ  Ayuda & Leyenda")

        self._build_startup_tab()
        self._build_services_tab()
        self._build_info_tab()

    # ── Tab: Programas de Inicio ─────────────────────────────
    def _build_startup_tab(self):
        f = self._tab_startup
        f.configure(style="TFrame")

        # Toolbar
        bar = tk.Frame(f, bg=COLORS["panel"], pady=6)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        self._btn_refresh_s = self._mk_btn(bar, "↻ Actualizar", self._load_startup, COLORS["blue"])
        self._btn_refresh_s.pack(side="left", padx=6)
        self._btn_disable_s = self._mk_btn(bar, "✘ Deshabilitar selección",
                                           lambda: self._toggle_startup(False), COLORS["red"])
        self._btn_disable_s.pack(side="left", padx=4)
        self._btn_enable_s  = self._mk_btn(bar, "✔ Habilitar selección",
                                           lambda: self._toggle_startup(True), COLORS["green"])
        self._btn_enable_s.pack(side="left", padx=4)
        self._btn_all_off_s = self._mk_btn(bar, "⛔ Deshabilitar TODO",
                                           self._disable_all_startup, "#7c3aed")
        self._btn_all_off_s.pack(side="left", padx=4)
        self._btn_all_on_s  = self._mk_btn(bar, "↩ Habilitar TODO",
                                           self._enable_all_startup, COLORS["yellow"])
        self._btn_all_on_s.pack(side="left", padx=4)
        self._btn_restore_s = self._mk_btn(bar, "🛡 Punto de Restauración",
                                           self._create_restore_point, "#0e7490")
        self._btn_restore_s.pack(side="left", padx=8)

        tk.Label(bar,
                 text="🔒 Protegido  |  🟢 Habilitado  |  🔴 Deshabilitado  |  Ctrl+clic = multi-selección",
                 bg=COLORS["panel"], fg=COLORS["subtext"],
                 font=("Segoe UI", 8)).pack(side="right", padx=10)

        # Treeview
        cols = ("Estado", "Nombre", "Origen", "Ruta/Comando", "Protegido")
        self._tv_start = ttk.Treeview(f, columns=cols, show="headings",
                                      selectmode="extended")
        widths = {"Estado": 80, "Nombre": 200, "Origen": 90, "Ruta/Comando": 440, "Protegido": 80}
        for c in cols:
            self._tv_start.heading(c, text=c,
                                   command=lambda _c=c: self._sort_tree(self._tv_start, _c))
            self._tv_start.column(c, width=widths[c], anchor="w")

        sb = ttk.Scrollbar(f, orient="vertical", command=self._tv_start.yview)
        self._tv_start.configure(yscrollcommand=sb.set)
        self._tv_start.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        sb.pack(side="right", fill="y", pady=6, padx=(0, 6))

        self._tv_start.tag_configure("enabled",   foreground=COLORS["green"])
        self._tv_start.tag_configure("disabled",  foreground=COLORS["red"])
        self._tv_start.tag_configure("protected", foreground=COLORS["gray"],
                                     background=COLORS["protected"])

        # Status bar
        self._status_s = tk.StringVar(value="Cargando...")
        tk.Label(f, textvariable=self._status_s, bg=COLORS["bg"],
                 fg=COLORS["subtext"], font=("Segoe UI", 8),
                 anchor="w").pack(fill="x", padx=8)

    # ── Tab: Servicios ───────────────────────────────────────
    def _build_services_tab(self):
        f = self._tab_services
        f.configure(style="TFrame")

        bar = tk.Frame(f, bg=COLORS["panel"], pady=6)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        self._btn_refresh_sv = self._mk_btn(bar, "↻ Actualizar", self._load_services, COLORS["blue"])
        self._btn_refresh_sv.pack(side="left", padx=6)
        self._btn_disable_sv = self._mk_btn(bar, "✘ Deshabilitar selección",
                                            lambda: self._toggle_service(False), COLORS["red"])
        self._btn_disable_sv.pack(side="left", padx=4)
        self._btn_enable_sv  = self._mk_btn(bar, "✔ Habilitar selección",
                                            lambda: self._toggle_service(True), COLORS["green"])
        self._btn_enable_sv.pack(side="left", padx=4)
        self._btn_all_off_sv = self._mk_btn(bar, "⛔ Deshabilitar TODO",
                                            self._disable_all_services, "#7c3aed")
        self._btn_all_off_sv.pack(side="left", padx=4)
        self._btn_all_on_sv  = self._mk_btn(bar, "↩ Habilitar TODO",
                                            self._enable_all_services, COLORS["yellow"])
        self._btn_all_on_sv.pack(side="left", padx=4)
        self._btn_restore_sv = self._mk_btn(bar, "🛡 Punto de Restauración",
                                            self._create_restore_point, "#0e7490")
        self._btn_restore_sv.pack(side="left", padx=8)

        # Filtro
        self._show_protected = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="Mostrar también los protegidos",
                       variable=self._show_protected,
                       command=self._refresh_services_view,
                       bg=COLORS["panel"], fg=COLORS["subtext"],
                       selectcolor=COLORS["accent"],
                       activebackground=COLORS["panel"],
                       font=("Segoe UI", 9)).pack(side="right", padx=10)

        cols = ("Estado", "Nombre del Servicio", "Nombre Interno", "Descripción", "Protegido")
        self._tv_svc = ttk.Treeview(f, columns=cols, show="headings",
                                    selectmode="extended")
        widths = {"Estado": 90, "Nombre del Servicio": 210, "Nombre Interno": 130,
                  "Descripción": 395, "Protegido": 80}
        for c in cols:
            self._tv_svc.heading(c, text=c)
            self._tv_svc.column(c, width=widths[c], anchor="w")

        sb2 = ttk.Scrollbar(f, orient="vertical", command=self._tv_svc.yview)
        self._tv_svc.configure(yscrollcommand=sb2.set)
        self._tv_svc.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        sb2.pack(side="right", fill="y", pady=6, padx=(0, 6))

        self._tv_svc.tag_configure("running",   foreground=COLORS["green"])
        self._tv_svc.tag_configure("stopped",   foreground=COLORS["orange"])
        self._tv_svc.tag_configure("disabled",  foreground=COLORS["red"])
        self._tv_svc.tag_configure("protected", foreground=COLORS["gray"],
                                   background=COLORS["protected"])

        self._status_sv = tk.StringVar(value="Cargando...")
        tk.Label(f, textvariable=self._status_sv, bg=COLORS["bg"],
                 fg=COLORS["subtext"], font=("Segoe UI", 8),
                 anchor="w").pack(fill="x", padx=8)

    # ── Tab: Información ─────────────────────────────────────
    def _build_info_tab(self):
        f = self._tab_info
        canvas = tk.Canvas(f, bg=COLORS["bg"], highlightthickness=0)
        vsb = ttk.Scrollbar(f, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=COLORS["bg"])
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        def section(title, lines, fg=COLORS["blue"]):
            tk.Label(inner, text=title, bg=COLORS["bg"], fg=fg,
                     font=("Segoe UI", 11, "bold"), anchor="w").pack(fill="x", padx=20, pady=(16, 2))
            tk.Frame(inner, bg=fg, height=1).pack(fill="x", padx=20)
            for line in lines:
                tk.Label(inner, text=line, bg=COLORS["bg"], fg=COLORS["text"],
                         font=("Segoe UI", 9), anchor="w", justify="left",
                         wraplength=980).pack(fill="x", padx=28, pady=1)

        section("¿Por qué sube el consumo de RAM al iniciar?", [
            "Windows debería estabilizarse entre 2.5–4.5 GB en reposo (depende de la versión y RAM total).",
            "Si superas los 6–8 GB, hay programas de inicio o servicios extras consumiendo memoria.",
            "Las principales causas: apps de terceros en la bandeja (Discord, Teams, Spotify, launchers de juegos,",
            "antivirus de pago, herramientas de OEM como Lenovo Vantage, HP Support, dell-*, etc.).",
        ])
        section("Leyenda de colores — Programas de Inicio", [
            "🟢 Verde   → El programa está habilitado en el inicio.",
            "🔴 Rojo    → El programa está deshabilitado (no se ejecutará al iniciar).",
            "⬜ Gris(fondo oscuro) → Elemento protegido del sistema: NO se puede modificar aquí.",
        ])
        section("Leyenda de colores — Servicios", [
            "🟢 Verde   → Servicio en ejecución (Automático).",
            "🟠 Naranja → Servicio detenido pero configurado como Automático.",
            "⬜ Gris(fondo oscuro) → Servicio crítico del sistema: bloqueado.",
        ])
        section("¿Qué es seguro deshabilitar?", [
            "• Programas de inicio: cualquiera que NO sea de Windows ni de tus drivers.",
            "  – Ejemplos seguros: Discord, Spotify, Steam, Epic Launcher, OneDrive* (si no lo usas),",
            "    Cortana launcher, Teams, apps de tu fabricante (MSI Center, Armoury Crate, etc.).",
            "• Servicios: solo los que aparecen en naranja SIN fondo gris.",
            "  – Telemetría (DiagTrack, dmwappushservice), Fax, Remote Registry, Xbox Live (si no juegas en PC).",
            "  – WSearch (Windows Search) reduce RAM pero ralentiza la búsqueda en el explorador.",
        ])
        section("🔒 Portabilidad — funciona en cualquier máquina", [
            "El script usa protección en DOS capas:",
            "",
            "  Servicios: lista explícita de ~100 nombres críticos de Windows (red, audio,",
            "             seguridad, Wi-Fi, teclado, etc.). Funciona en Win 10/11 de cualquier marca.",
            "             NOTA: no se usa protección por ruta en servicios porque la mayoría",
            "             (incluyendo los de terceros) corren dentro de svchost.exe en System32,",
            "             lo que haría que TODOS quedaran bloqueados y la lista aparecería vacía.",
            "",
            "  Inicio:    protección por nombre explícito + por ruta del ejecutable.",
            "             Cualquier programa en System32 / SysWOW64 queda bloqueado automáticamente.",
        ], fg=COLORS["blue"])
        section("¿Qué NO se puede tocar desde aquí?", [
            "• Nada con ruta en System32 / SysWOW64 / drivers está disponible para deshabilitar.",
            "• Servicios marcados como protegidos (fondo gris) cubren: Wi-Fi, Ethernet, Audio,",
            "  Seguridad, Actualizaciones, DWM (escritorio), RPC, EventLog, PnP, Energía,",
            "  teclado (HID), conexiones de red (WlanSvc, Wcmsvc, Netman, nsi, iphlpsvc, etc.),",
            "  autenticación (SamSs), Bluetooth y más.",
            "• Cualquier componente cuya desactivación rompería el arranque o el uso básico de Windows.",
        ])
        section("🛡 Nuevas protecciones de seguridad (v2)", [
            "• Wi-Fi (WlanSvc), Ethernet/red (Wcmsvc, Netman, nsi, iphlpsvc) ahora están PROTEGIDOS.",
            "  En versiones anteriores se podían deshabilitar accidentalmente.",
            "• '↩ Habilitar TODO' ahora SOLO restaura servicios que ESTA app deshabilitó.",
            "  Ya no toca servicios que Windows desactivó por su cuenta.",
            "• El archivo de seguimiento se guarda en: %APPDATA%\\StartupManagerNiko\\services_log.json",
            "• Los atajos de carpeta de inicio deshabilitados ahora se ven y pueden re-habilitarse",
            "  incluso al reiniciar el programa (no desaparecen de la vista como antes).",
            "• Botón '🛡 Punto de Restauración': crea un punto de restauración ANTES de hacer cambios.",
            "  Úsalo siempre que vayas a deshabilitar servicios por primera vez.",
        ], fg=COLORS["green"])
        section("Consejo adicional", [
            "Tras deshabilitar programas de inicio, reinicia y mide la RAM con el Administrador de tareas.",
            "Si algo falla, este programa puede volver a habilitar cualquier elemento deshabilitado.",
            "Para servicios, si deshabilitas uno que needed, vuelve aquí y usa '✔ Habilitar servicio'.",
        ], fg=COLORS["yellow"])

    # ── Helpers UI ───────────────────────────────────────────
    def _mk_btn(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd,
                         bg=color, fg="white", relief="flat",
                         font=("Segoe UI", 9, "bold"),
                         padx=10, pady=4, cursor="hand2",
                         activebackground=COLORS["bg"],
                         activeforeground=color)

    def _create_restore_point(self):
        """Crea un punto de restauración del sistema de Windows."""
        if not is_admin():
            messagebox.showerror("Sin permisos",
                "Necesitas ejecutar como Administrador para crear un Punto de Restauración.\n"
                "Reinicia el programa con permisos de administrador.", parent=self)
            return
        if not messagebox.askyesno("🛡 Crear Punto de Restauración",
            "Se creará un Punto de Restauración del Sistema de Windows.\n\n"
            "Esto te permitirá deshacer cualquier cambio en caso de problemas.\n"
            "El proceso puede tardar unos segundos.\n\n"
            "¿Continuar?", parent=self):
            return
        self._status_s.set("Creando Punto de Restauración... (puede tardar 30-60 seg.)")
        self._status_sv.set("Creando Punto de Restauración... (puede tardar 30-60 seg.)")
        self.update_idletasks()
        def task():
            ok = create_restore_point("Startup Manager — Niko Vanetti")
            def done():
                if ok:
                    self._status_s.set("")
                    self._status_sv.set("")
                    messagebox.showinfo("✅ Punto de Restauración creado",
                        "Punto de Restauración creado exitosamente.\n\n"
                        "Para restaurar si algo falla:\n"
                        "Inicio → Buscar 'Crear un punto de restauración' → Restaurar sistema.",
                        parent=self)
                else:
                    self._status_s.set("")
                    self._status_sv.set("")
                    messagebox.showwarning("Advertencia",
                        "No se pudo crear el Punto de Restauración automáticamente.\n\n"
                        "Es posible que la Protección del Sistema esté deshabilitada en C:.\n"
                        "Para habilitarla:\n"
                        "  1. Busca 'Crear un punto de restauración' en el menú Inicio.\n"
                        "  2. Selecciona C: y haz clic en 'Configurar'.\n"
                        "  3. Activa 'Activar protección del sistema'.",
                        parent=self)
            self.after(0, done)
        threading.Thread(target=task, daemon=True).start()

    def _sort_tree(self, tv, col):
        items = [(tv.set(k, col), k) for k in tv.get_children("")]
        items.sort()
        for idx, (_, k) in enumerate(items):
            tv.move(k, "", idx)

    # ── Load All ─────────────────────────────────────────────
    def _load_all(self):
        self._update_ram()
        self._load_startup()
        self._load_services()

    def _update_ram(self):
        def task():
            info = get_ram_info()
            self.after(0, lambda: self._ram_lbl.configure(
                text=f"RAM: {info['used']:.1f} GB usados / {info['total']:.1f} GB total  ({info['pct']:.0f}%)"
            ))
        threading.Thread(target=task, daemon=True).start()

    # ── Startup Loading ──────────────────────────────────────
    def _load_startup(self):
        self._status_s.set("Escaneando programas de inicio...")
        self._btn_refresh_s.configure(state="disabled")
        def task():
            items = get_startup_items()
            self.after(0, lambda: self._populate_startup(items))
        threading.Thread(target=task, daemon=True).start()

    def _populate_startup(self, items):
        self._startup_items   = items
        self._startup_iid_map = {}
        tv = self._tv_start
        for row in tv.get_children():
            tv.delete(row)
        enabled_count  = 0
        disabled_count = 0
        for item in items:
            prot  = item["protected"]
            enab  = item["enabled"]
            estado = "🔒 Protegido" if prot else ("🟢 Hab." if enab else "🔴 Deshabilitado")
            tag   = "protected" if prot else ("enabled" if enab else "disabled")
            ruta  = item["value"][:80] + ("…" if len(item["value"]) > 80 else "")
            iid = tv.insert("", "end",
                      values=(estado, item["name"], item["source"], ruta, "Sí" if prot else "No"),
                      tags=(tag,))
            self._startup_iid_map[iid] = item
            if not prot:
                if enab:
                    enabled_count += 1
                else:
                    disabled_count += 1
        protected_count = sum(1 for i in items if i["protected"])
        self._status_s.set(
            f"Total: {len(items)}  |  Habilitados: {enabled_count}  |  "
            f"Deshabilitados: {disabled_count}  |  Protegidos: {protected_count}"
        )
        self._btn_refresh_s.configure(state="normal")
        self._update_ram()

    def _toggle_startup(self, enable: bool):
        sel = self._tv_start.selection()
        if not sel:
            messagebox.showinfo("Selección",
                "Selecciona uno o más elementos primero.\n(Ctrl+clic para selección múltiple)",
                parent=self)
            return
        items_to_do = []
        skipped = 0
        for iid in sel:
            item = self._startup_iid_map.get(iid)
            if item:
                if item["protected"]:
                    skipped += 1
                else:
                    items_to_do.append(item)
        if not items_to_do:
            messagebox.showwarning("Protegidos",
                "Todos los elementos seleccionados son del sistema y no se pueden modificar.",
                parent=self)
            return
        accion = "habilitar" if enable else "deshabilitar"
        if len(items_to_do) == 1:
            msg = (f"¿Deseas {accion} '{items_to_do[0]['name']}'?\n\n"
                   f"Ruta: {items_to_do[0]['value'][:120]}")
        else:
            names = "\n".join(f"  • {i['name']}" for i in items_to_do[:15])
            if len(items_to_do) > 15:
                names += f"\n  ... y {len(items_to_do)-15} más"
            msg = f"¿Deseas {accion} {len(items_to_do)} elemento(s)?\n\n{names}"
            if skipped:
                msg += f"\n\n({skipped} protegidos del sistema serán ignorados)"
        if not messagebox.askyesno("Confirmar", msg, parent=self):
            return
        errors = []
        for item in items_to_do:
            try:
                toggle_startup_item(item, enable)
                item["enabled"] = enable
            except Exception as e:
                errors.append(f"{item['name']}: {e}")
        self._populate_startup(self._startup_items)
        n = len(items_to_do) - len(errors)
        if errors:
            messagebox.showerror("Errores parciales", "\n".join(errors), parent=self)
        else:
            messagebox.showinfo("Listo",
                f"{n} elemento(s) {'habilitados' if enable else 'deshabilitados'}.\n"
                "El cambio tendrá efecto en el próximo inicio de Windows.", parent=self)

    # ── Services Loading ─────────────────────────────────────
    def _load_services(self):
        self._status_sv.set("Escaneando servicios...")
        self._btn_refresh_sv.configure(state="disabled")
        def task():
            svcs = get_services()
            self.after(0, lambda: self._store_and_show_services(svcs))
        threading.Thread(target=task, daemon=True).start()

    def _store_and_show_services(self, svcs):
        self._services = svcs
        self._refresh_services_view()
        for btn in (self._btn_refresh_sv, self._btn_disable_sv, self._btn_enable_sv,
                    self._btn_all_off_sv, self._btn_all_on_sv, self._btn_restore_sv):
            btn.configure(state="normal")

    def _refresh_services_view(self):
        tv = self._tv_svc
        self._service_iid_map = {}
        for row in tv.get_children():
            tv.delete(row)
        show_prot = self._show_protected.get()
        visible = [s for s in self._services if show_prot or not s["protected"]]
        for svc in visible:
            prot    = svc["protected"]
            enabled = svc["enabled"]
            # Usar el status ya calculado en get_services()
            estado  = svc["status"]
            desc    = svc["description"] or svc["display"]
            if prot:
                tag = "protected"
            elif not enabled:
                tag = "disabled"
            elif svc["running"]:
                tag = "running"
            else:
                tag = "stopped"
            iid = tv.insert("", "end",
                      values=(estado, svc["display"][:35], svc["name"],
                               desc[:70], "Sí" if prot else "No"),
                      tags=(tag,))
            self._service_iid_map[iid] = svc
        total_non_prot  = sum(1 for s in self._services if not s["protected"])
        total_protected = sum(1 for s in self._services if s["protected"])
        total_disabled  = sum(1 for s in self._services if not s["protected"] and not s["enabled"])
        self._status_sv.set(
            f"Servicios: {len(self._services)}  |  "
            f"Modificables: {total_non_prot}  |  "
            f"Deshabilitados por esta app: {total_disabled}  |  "
            f"Protegidos: {total_protected}"
        )
        self._update_ram()

    def _toggle_service(self, enable: bool):
        sel = self._tv_svc.selection()
        if not sel:
            messagebox.showinfo("Selección",
                "Selecciona uno o más servicios primero.\n(Ctrl+clic para selección múltiple)",
                parent=self)
            return
        if not is_admin():
            messagebox.showerror("Sin permisos",
                "Para modificar servicios necesitas ejecutar el programa como Administrador.\n"
                "Usa el archivo INICIAR_STARTUP_MANAGER.bat para abrirlo con permisos.",
                parent=self)
            return
        svcs_to_do = []
        skipped = 0
        for iid in sel:
            svc = self._service_iid_map.get(iid)
            if svc:
                if svc["protected"]:
                    skipped += 1
                else:
                    svcs_to_do.append(svc)
        if not svcs_to_do:
            messagebox.showwarning("Protegidos",
                "Todos los servicios seleccionados son críticos del sistema y no se pueden modificar.",
                parent=self)
            return
        accion = "habilitar" if enable else "deshabilitar"
        if len(svcs_to_do) == 1:
            svc = svcs_to_do[0]
            msg = f"¿Deseas {accion} '{svc['display']}'?\nNombre interno: {svc['name']}"
        else:
            names = "\n".join(f"  • {s['display']}" for s in svcs_to_do[:15])
            if len(svcs_to_do) > 15:
                names += f"\n  ... y {len(svcs_to_do)-15} más"
            msg = f"¿Deseas {accion} {len(svcs_to_do)} servicio(s)?\n\n{names}"
            if skipped:
                msg += f"\n\n({skipped} protegidos del sistema serán ignorados)"
        if not messagebox.askyesno("Confirmar", msg, parent=self):
            return
        self._run_service_batch(svcs_to_do, enable)

    def _run_service_batch(self, svcs: list, enable: bool):
        """Ejecuta cambio de inicio sobre una lista de servicios en un hilo separado."""
        total  = len(svcs)
        accion = "habilitando" if enable else "deshabilitando"
        self._status_sv.set(f"{accion.capitalize()} {total} servicio(s)...")
        for btn in (self._btn_disable_sv, self._btn_enable_sv,
                    self._btn_all_off_sv, self._btn_all_on_sv, self._btn_refresh_sv,
                    self._btn_restore_sv):
            btn.configure(state="disabled")
        def task():
            errors = []
            done   = 0
            for i, svc in enumerate(svcs, 1):
                try:
                    toggle_service(svc["name"], enable)
                    done += 1
                except Exception as e:
                    errors.append(f"{svc['name']}: {e}")
                if i % 3 == 0 or i == total:
                    self.after(0, lambda i=i: self._status_sv.set(
                        f"Procesando {i}/{total}..."
                    ))
            def finish():
                self._load_services()
                n = done
                if errors:
                    msg = (f"{n} servicio(s) {'habilitados' if enable else 'deshabilitados'}.\n"
                           f"Errores en {len(errors)}:\n" + "\n".join(errors[:8]))
                    messagebox.showerror("Completado con errores", msg, parent=self)
                else:
                    messagebox.showinfo("Listo",
                        f"{n} servicio(s) {'habilitados' if enable else 'deshabilitados'} correctamente.",
                        parent=self)
            self.after(0, finish)
        threading.Thread(target=task, daemon=True).start()

    def _disable_all_services(self):
        if not is_admin():
            messagebox.showerror("Sin permisos",
                "Necesitas ejecutar como Administrador para modificar servicios.\n"
                "Usa el archivo INICIAR_STARTUP_MANAGER.bat.", parent=self)
            return
        targets = [s for s in self._services if not s["protected"]]
        if not targets:
            messagebox.showinfo("Sin elementos", "No hay servicios modificables.", parent=self)
            return
        names = "\n".join(f"  • {s['display']}" for s in targets[:22])
        if len(targets) > 22:
            names += f"\n  ... y {len(targets)-22} más"
        # Confirmación reforzada con advertencia de riesgo
        confirm = messagebox.askyesno(
            "⚠ ADVERTENCIA — Deshabilitar inicio automático de servicios",
            f"Se deshabilitará el inicio automático de {len(targets)} servicios NO protegidos.\n\n"
            f"✅ Los servicios CRÍTICOS de Windows (red, audio, seguridad, WiFi, teclado, etc.)\n"
            f"   ya están protegidos y NO serán afectados.\n\n"
            f"⚠ Aun así, algunos servicios en la lista podrían ser necesarios para TU uso,\n"
            f"   por ejemplo: impresión, Bluetooth, escritorio remoto, etc.\n\n"
            f"Servicios que se deshabilitarán:\n{names}\n\n"
            f"RECOMENDACIÓN: Crea un Punto de Restauración antes (botón '🛡 Punto de Restauración').\n"
            f"Podrás revertir TODOS estos cambios con '↩ Habilitar TODO' en cualquier momento.\n\n"
            f"¿Confirmar?",
            icon="warning", parent=self)
        if not confirm:
            return
        self._run_service_batch(targets, False)

    def _enable_all_services(self):
        if not is_admin():
            messagebox.showerror("Sin permisos",
                "Necesitas ejecutar como Administrador para modificar servicios.\n"
                "Usa el archivo INICIAR_STARTUP_MANAGER.bat.", parent=self)
            return
        # SEGURIDAD CRÍTICA: solo re-habilitar los que ESTA APP deshabilitó.
        # No tocamos servicios que Windows desactivó por su cuenta.
        app_disabled = get_services_disabled_by_app()
        if not app_disabled:
            messagebox.showinfo("Sin cambios propios",
                "Este programa no tiene registrado haber deshabilitado ningún servicio.\n\n"
                "Si deshabilitaste servicios manualmente o con otro programa, "
                "usa el Administrador de Servicios de Windows (services.msc) para revertirlos.",
                parent=self)
            return
        # Construir lista de targets filtrando protegidos
        targets = [
            {"name": name, "display": name, "protected": False, "running": False}
            for name in app_disabled
            if name.lower() not in PROTECTED_SERVICES_LOWER
        ]
        if not targets:
            messagebox.showinfo("Sin elementos",
                "No hay servicios para re-habilitar.", parent=self)
            return
        names = "\n".join(f"  • {s['name']}" for s in targets[:22])
        if len(targets) > 22:
            names += f"\n  ... y {len(targets)-22} más"
        if not messagebox.askyesno("↩ Habilitar servicios deshabilitados por esta app",
            f"Se re-habilitará el inicio automático de {len(targets)} servicio(s) "
            f"que ESTE programa deshabilitó:\n\n"
            f"{names}\n\n"
            f"Servicios deshabilitados por Windows o por otros programas NO serán tocados.\n\n"
            f"¿Continuar?", parent=self):
            return
        self._run_service_batch(targets, True)

    def _disable_all_startup(self):
        targets = [i for i in self._startup_items if not i["protected"] and i["enabled"]]
        if not targets:
            messagebox.showinfo("Sin elementos",
                "No hay programas de inicio habilitados para deshabilitar.", parent=self)
            return
        names = "\n".join(f"  • {i['name']}" for i in targets[:22])
        if len(targets) > 22:
            names += f"\n  ... y {len(targets)-22} más"
        if not messagebox.askyesno("⚠ Deshabilitar TODO el inicio",
            f"Se deshabilitarán {len(targets)} programa(s) de inicio no protegidos.\n\n"
            f"✅ Programas del SISTEMA (rutas de System32, SysWOW64, etc.) están protegidos\n"
            f"   y NO serán afectados.\n\n"
            f"Podrás revertirlo con '↩ Habilitar TODO' en cualquier momento.\n\n"
            f"Afectados:\n{names}\n\n¿Confirmar?",
            icon="warning", parent=self):
            return
        errors = []
        for item in targets:
            try:
                toggle_startup_item(item, False)
                item["enabled"] = False
            except Exception as e:
                errors.append(f"{item['name']}: {e}")
        self._populate_startup(self._startup_items)
        n = len(targets) - len(errors)
        if errors:
            messagebox.showerror("Errores parciales",
                f"{n} deshabilitados.\nErrores:\n" + "\n".join(errors[:5]), parent=self)
        else:
            messagebox.showinfo("Listo",
                f"{n} programas de inicio deshabilitados.\n"
                "El cambio tendrá efecto en el próximo inicio de Windows.", parent=self)

    def _enable_all_startup(self):
        targets = [i for i in self._startup_items if not i["protected"] and not i["enabled"]]
        if not targets:
            messagebox.showinfo("Sin elementos",
                "No hay programas de inicio deshabilitados para habilitar.", parent=self)
            return
        names = "\n".join(f"  • {i['name']}" for i in targets[:22])
        if len(targets) > 22:
            names += f"\n  ... y {len(targets)-22} más"
        if not messagebox.askyesno("↩ Habilitar TODO el inicio",
            f"Se re-habilitarán {len(targets)} programa(s) de inicio:\n\n{names}\n\n¿Continuar?",
            parent=self):
            return
        errors = []
        for item in targets:
            try:
                toggle_startup_item(item, True)
                item["enabled"] = True
            except Exception as e:
                errors.append(f"{item['name']}: {e}")
        self._populate_startup(self._startup_items)
        n = len(targets) - len(errors)
        if errors:
            messagebox.showerror("Errores parciales",
                f"{n} habilitados.\nErrores:\n" + "\n".join(errors[:5]), parent=self)
        else:
            messagebox.showinfo("Listo",
                f"{n} programas de inicio habilitados.\n"
                "El cambio tendrá efecto en el próximo inicio de Windows.", parent=self)


# ──────────────────────────────────────────────────────────────
#  ENTRADA PRINCIPAL
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not is_admin():
        answer = messagebox.askyesno(
            "Privilegios de Administrador",
            "Para modificar servicios del sistema se recomienda ejecutar como Administrador.\n\n"
            "¿Deseas reiniciar como Administrador ahora?\n"
            "(Si dices 'No', podrás ver y gestionar programas de inicio de tu usuario,\n"
            "pero NO podrás modificar servicios del sistema.)",
            icon="warning"
        )
        if answer:
            elevate()
    app = StartupManagerApp()
    app.mainloop()
