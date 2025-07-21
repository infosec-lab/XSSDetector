@echo off
rem ------------------------------------------------------------
rem  XSSDetector – Build Script (Windows)
rem  Author : Vikas Kumar
rem  Version: 2025.1.0 (AI Edition)
rem ------------------------------------------------------------

rem === Configuration =========================================
setlocal enabledelayedexpansion
set "SRC_DIR=src"
set "PKG_DIR=burp"
set "BUILD_DIR=build"
set "CLASS_DIR=%BUILD_DIR%\classes"
set "DIST_DIR=dist"
set "JAR_NAME=XSSDetector.jar"
rem ============================================================

echo.
echo -------- Building %JAR_NAME% --------

rem Prepare folders
for %%D in ("%CLASS_DIR%" "%DIST_DIR%") do if not exist "%%~D" mkdir "%%~D"

rem Clean previous output
del /q "%CLASS_DIR%\*" 2>nul
del /q "%DIST_DIR%\%JAR_NAME%" 2>nul

echo [1/3] Compiling …
javac -d "%CLASS_DIR%" -cp "%SRC_DIR%" "%SRC_DIR%\%PKG_DIR%\*.java"
if errorlevel 1 (
    echo ERROR: Compilation failed.
    goto :eof
)
echo     ✓ Compilation succeeded

echo [2/3] Packaging …
jar cvf "%DIST_DIR%\%JAR_NAME%" -C "%CLASS_DIR%" .
if errorlevel 1 (
    echo ERROR: JAR creation failed.
    goto :eof
)
echo     ✓ JAR created

echo [3/3] Verifying …
jar tf "%DIST_DIR%\%JAR_NAME%" >nul || (
    echo ERROR: Verification failed.
    goto :eof
)
for %%A in ("%DIST_DIR%\%JAR_NAME%") do set "SIZE=%%~zA"

echo.
echo -------- Build Complete --------
echo Artifact : %cd%\%DIST_DIR%\%JAR_NAME%
echo Size     : !SIZE! bytes
echo ---------------------------------
echo Load into Burp Suite:
echo   Extender ► Extensions ► Add ► Java ► browse to JAR
echo ---------------------------------
pause
endlocal
