@echo off
setlocal
cd /d "%~dp0"
set "PYEXE=%~dp0.venv\Scripts\python.exe"
if exist "%PYEXE%" (
  "%PYEXE%" "%~dp0osint_intelligence_v5.py" %*
  exit /b %ERRORLEVEL%
)
where py >nul 2>&1 && (
  py -3 "%~dp0osint_intelligence_v5.py" %*
  exit /b %ERRORLEVEL%
)
where python >nul 2>&1 && (
  python "%~dp0osint_intelligence_v5.py" %*
  exit /b %ERRORLEVEL%
)
echo No se encontro Python. Opciones:
echo   1) Crear venv: py -3 -m venv .venv
echo   2) Desactivar alias: Configuracion -^> Aplicaciones -^> Alias de ejecucion -^> desactivar "python.exe" de la Store
echo   3) Ejecutar: "%~dp0.venv\Scripts\python.exe" osint_intelligence_v5.py
exit /b 9009
