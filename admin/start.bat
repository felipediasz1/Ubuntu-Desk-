@echo off
:: Ubuntu Desk — Admin Panel (Windows)
:: Uso: start.bat
:: Variaveis opcionais: ADMIN_PASSWORD, PORT, DB_PATH, SECRET_KEY

setlocal

cd /d "%~dp0"

:: Verificar Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERRO] Python nao encontrado no PATH.
    echo Instale o Python em https://python.org
    pause
    exit /b 1
)

:: Instalar Flask se necessario
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Instalando Flask...
    python -m pip install flask --quiet
)

:: Valores padrao
if not defined ADMIN_PASSWORD set ADMIN_PASSWORD=ubuntu-desk-admin
if not defined PORT           set PORT=8088
if not defined SECRET_KEY     set SECRET_KEY=mude-esta-chave-em-producao

echo.
echo  ========================================
echo   Ubuntu Desk - Painel de Administracao
echo  ========================================
echo   URL:   http://localhost:%PORT%
echo   Senha: %ADMIN_PASSWORD%
echo.
echo  Pressione Ctrl+C para parar.
echo.

python app.py
pause
