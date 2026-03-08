@echo off
setlocal EnableDelayedExpansion
title Startup Manager - Niko Vanetti — Buscando Python...

REM ══════════════════════════════════════════════════════════════
REM  Lanzador de Startup Manager con deteccion automatica de Python
REM  Busca Python en el orden correcto en cualquier maquina.
REM ══════════════════════════════════════════════════════════════

set "SCRIPT=%~dp0startup_manager.py"
set "PYTHON_EXE="

REM ── 1. Python Launcher oficial de Windows (py.exe) ────────────
REM    El instalador estandar de python.org lo incluye siempre.
where /q py.exe 2>nul
if !errorlevel! == 0 (
    py.exe --version >nul 2>nul
    if !errorlevel! == 0 (
        set "PYTHON_EXE=py.exe"
        goto :found
    )
)

REM ── 2. Python en rutas estandar del instalador python.org ─────
for %%V in (313 312 311 310 39 38) do (
    if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
        goto :found
    )
    if exist "C:\Python%%V\python.exe" (
        set "PYTHON_EXE=C:\Python%%V\python.exe"
        goto :found
    )
    if exist "%ProgramFiles%\Python%%V\python.exe" (
        set "PYTHON_EXE=%ProgramFiles%\Python%%V\python.exe"
        goto :found
    )
)

REM ── 3. Python de MSYS2 / MinGW ────────────────────────────────
if exist "C:\msys64\mingw64\bin\python.exe" (
    set "PYTHON_EXE=C:\msys64\mingw64\bin\python.exe"
    goto :found
)
if exist "C:\msys64\usr\bin\python3.exe" (
    set "PYTHON_EXE=C:\msys64\usr\bin\python3.exe"
    goto :found
)
if exist "C:\msys2\mingw64\bin\python.exe" (
    set "PYTHON_EXE=C:\msys2\mingw64\bin\python.exe"
    goto :found
)

REM ── 4. python.exe en el PATH (excluir alias de WindowsApps) ───
for /f "delims=" %%P in ('where python.exe 2^>nul') do (
    echo %%P | findstr /i "WindowsApps" >nul
    if !errorlevel! neq 0 (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
    )
)
if defined PYTHON_EXE goto :found

REM ── 5. Conda / Anaconda ────────────────────────────────────────
if exist "%USERPROFILE%\anaconda3\python.exe" (
    set "PYTHON_EXE=%USERPROFILE%\anaconda3\python.exe"
    goto :found
)
if exist "%USERPROFILE%\miniconda3\python.exe" (
    set "PYTHON_EXE=%USERPROFILE%\miniconda3\python.exe"
    goto :found
)
if exist "%ProgramData%\Anaconda3\python.exe" (
    set "PYTHON_EXE=%ProgramData%\Anaconda3\python.exe"
    goto :found
)

REM ── Python no encontrado ───────────────────────────────────────
echo.
echo  [ERROR] No se encontro Python instalado en esta maquina.
echo.
echo  Para usar Startup Manager necesitas instalar Python:
echo    1. Ve a https://www.python.org/downloads/
echo    2. Descarga Python 3.10 o superior
echo    3. En la instalacion, marca "Add Python to PATH"
echo    4. Vuelve a ejecutar este archivo .bat
echo.
pause
exit /b 1

:found
REM ══════════════════════════════════════════════════════════════
REM  Python encontrado — lanzar el script como Administrador
REM ══════════════════════════════════════════════════════════════
PowerShell -NoProfile -Command "Start-Process -FilePath '!PYTHON_EXE!' -ArgumentList '\"!SCRIPT!\"' -Verb RunAs -WindowStyle Hidden"

if !errorlevel! neq 0 (
    echo.
    echo  [AVISO] No se pudo lanzar como Administrador.
    echo  Iniciando sin permisos elevados ^(funciones limitadas^)...
    "!PYTHON_EXE!" "!SCRIPT!"
)

endlocal
