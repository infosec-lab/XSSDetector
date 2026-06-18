@echo off
rem ------------------------------------------------------------
rem  XSSDetector – Build Script (Windows)
rem  Version: 2.0.0 (AI Edition)
rem ------------------------------------------------------------

rem === Configuration =========================================
setlocal enabledelayedexpansion
set "SRC_DIR=src"
set "PKG_DIR=burp"
set "BUILD_DIR=build"
set "CLASS_DIR=%BUILD_DIR%\classes"
set "DIST_DIR=dist"
set "VERSION=2.0.0"
set "JAR_NAME=XSSDetector.jar"
rem ============================================================

echo.
echo -------- Building %JAR_NAME% --------

rem Prepare folders
for %%D in ("%CLASS_DIR%" "%DIST_DIR%") do if not exist "%%~D" mkdir "%%~D"

rem Clean previous output
echo Cleaning previous build...
if exist "%CLASS_DIR%" (
    del /q /s "%CLASS_DIR%\*" 2>nul
    for /d %%D in ("%CLASS_DIR%\*") do rmdir /s /q "%%D" 2>nul
)
if exist "%DIST_DIR%\%JAR_NAME%" (
    del /q "%DIST_DIR%\%JAR_NAME%" 2>nul
    echo     ✓ Cleaned previous JAR
)

echo [1/3] Compiling …
rem Ensure Java 11 target for Burp Suite compatibility (class file version 55.0)
rem Using --release 11 ensures proper system module location for JDK 11 compatibility
rem CRITICAL FIX: Windows doesn't expand wildcards in quotes - use a file list approach
echo Checking Java files...
set "JAVA_COUNT=0"
for %%F in ("%SRC_DIR%\%PKG_DIR%\*.java") do (
    set /a JAVA_COUNT+=1
)
if !JAVA_COUNT!==0 (
    echo ERROR: No Java files found in %SRC_DIR%\%PKG_DIR%\
    pause
    goto :eof
)
echo Found !JAVA_COUNT! Java file(s) to compile
rem Use wildcard without quotes - Windows cmd.exe will expand it
cd /d "%SRC_DIR%\%PKG_DIR%"
javac --release 11 -d "%~dp0%CLASS_DIR%" -cp "%~dp0%SRC_DIR%" *.java
if errorlevel 1 (
    echo ERROR: Compilation failed. Check errors above.
    cd /d "%~dp0"
    pause
    goto :eof
)
cd /d "%~dp0"
echo     ✓ Compilation succeeded (Java 11 target)

echo [2/3] Packaging …
rem Find jar.exe automatically
where jar.exe >nul 2>&1
if errorlevel 1 (
    rem Try to find jar in common Java locations
    if exist "%JAVA_HOME%\bin\jar.exe" (
        set "JAR_CMD=%JAVA_HOME%\bin\jar.exe"
    ) else if exist "C:\Program Files\Java\jdk-25\bin\jar.exe" (
        set "JAR_CMD=C:\Program Files\Java\jdk-25\bin\jar.exe"
    ) else if exist "C:\Program Files\Java\jdk-17\bin\jar.exe" (
        set "JAR_CMD=C:\Program Files\Java\jdk-17\bin\jar.exe"
    ) else if exist "C:\Program Files\Java\jdk-11\bin\jar.exe" (
        set "JAR_CMD=C:\Program Files\Java\jdk-11\bin\jar.exe"
    ) else (
        echo ERROR: jar.exe not found. Please ensure Java JDK is installed.
        echo Checking common locations...
        if exist "%JAVA_HOME%" (
            echo JAVA_HOME is set to: %JAVA_HOME%
        ) else (
            echo JAVA_HOME is not set.
        )
        pause
        goto :eof
    )
) else (
    set "JAR_CMD=jar.exe"
)
echo Using jar command: %JAR_CMD%
echo Creating JAR from: %CLASS_DIR%
"%JAR_CMD%" cvf "%DIST_DIR%\%JAR_NAME%" -C "%CLASS_DIR%" .
if errorlevel 1 (
    echo ERROR: JAR creation failed. Check errors above.
    pause
    goto :eof
)
if not exist "%DIST_DIR%\%JAR_NAME%" (
    echo ERROR: JAR file was not created at: %DIST_DIR%\%JAR_NAME%
    pause
    goto :eof
)
echo     ✓ JAR created successfully

echo [3/3] Verifying …
if not exist "%DIST_DIR%\%JAR_NAME%" (
    echo ERROR: JAR file does not exist: %DIST_DIR%\%JAR_NAME%
    pause
    goto :eof
)
"%JAR_CMD%" tf "%DIST_DIR%\%JAR_NAME%" >nul 2>&1
if errorlevel 1 (
    echo ERROR: JAR verification failed - JAR file may be corrupted.
    pause
    goto :eof
)
for %%A in ("%DIST_DIR%\%JAR_NAME%") do set "SIZE=%%~zA"
if "!SIZE!"=="" (
    echo WARNING: Could not determine JAR file size.
    set "SIZE=unknown"
)

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
