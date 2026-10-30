@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   Configuracao do Ambiente - Active Directory MCP Server
echo ========================================================

echo [1/4] Verificando instalacao do Python...
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERRO] Python nao foi encontrado no PATH do sistema.
    echo Instale o Python 3.11 ou 3.12+ e certifique-se de adiciona-lo ao PATH.
    pause
    exit /b 1
)

echo [2/4] Criando ambiente virtual (.venv)...
if not exist ".venv" (
    python -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERRO] Falha ao criar ambiente virtual com 'python -m venv .venv'.
        pause
        exit /b 1
    )
) else (
    echo   Ambiente virtual .venv ja existe.
)

echo [3/4] Atualizando pip...
call .venv\Scripts\python.exe -m pip install --upgrade pip >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERRO] Falha ao atualizar o pip no ambiente virtual.
    pause
    exit /b 1
)

echo [4/4] Instalando dependencias do requirements.txt...
call .venv\Scripts\python.exe -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERRO] Falha ao instalar dependencias listadas no requirements.txt.
    pause
    exit /b 1
)

call .venv\Scripts\python.exe -m pip install -e . --no-deps >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERRO] Falha ao registrar o modulo ad_mcp.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   Ambiente configurado com sucesso!
echo ========================================================
echo   Para rodar a suite de testes:
echo     .venv\Scripts\pytest -v
echo   Para salvar credenciais no cofre do Windows:
echo     powershell -ExecutionPolicy Bypass -File scripts\set_production_credentials.ps1
echo ========================================================
