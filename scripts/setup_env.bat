@echo off
REM Setup virtual environment and dependencies for Microsoft Active Directory MCP Server
echo [1/3] Creating virtual environment...
python -m venv .venv

echo [2/3] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [3/3] Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

echo.
echo Active Directory MCP Server setup successfully completed!
echo To run the server:
echo   .venv\Scripts\python -m ad_mcp
pause

