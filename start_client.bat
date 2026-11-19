@echo off
title KVM Client Setup
echo ========================================
echo  KVM over VPN - Cliente
echo ========================================
echo.

:: Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Ejecuta como Administrador.
    pause
    exit /b 1
)

:: Install deps silently if missing
python -c "import win32clipboard" >nul 2>&1
if %errorlevel% neq 0 (
    echo Instalando dependencias...
    pip install pywin32 -q
)

:: Get Surfshark IP of SERVER
echo Ingresa el IP Surfshark del SERVIDOR (ej: 10.14.x.x):
set /p SERVER_IP=IP:

if "%SERVER_IP%"=="" (
    echo ERROR: IP no puede estar vacio.
    pause
    exit /b 1
)

echo.
echo Conectando a %SERVER_IP%:9876 en segundo plano...
start "" /b pythonw kvm_client.py --host %SERVER_IP%

echo.
echo Cliente corriendo en background.
echo Para detenerlo: taskkill /f /im pythonw.exe
echo.
pause
