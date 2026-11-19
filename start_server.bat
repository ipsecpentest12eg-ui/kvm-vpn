@echo off
title KVM Server
echo ========================================
echo  KVM over VPN - Servidor
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

:: Show Surfshark IP so user can give it to the client
echo Tu IP Surfshark (dale esta al cliente):
ipconfig | findstr "10\."
echo.

:: Open firewall rule (silent, ok if already exists)
netsh advfirewall firewall add rule name="KVM VPN" dir=in action=allow protocol=TCP localport=9876 >nul 2>&1

echo Iniciando servidor en puerto 9876...
echo Mueve el cursor al borde DERECHO para pasar al cliente.
echo ScrollLock = volver | Pause/Break = salir
echo.
python kvm_server.py
pause
