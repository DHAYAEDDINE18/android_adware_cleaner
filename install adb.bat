@echo off
setlocal enabledelayedexpansion

:: Step 1: Set download URL
set "URL=https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
set "ZIP_FILE=%TEMP%\platform-tools.zip"
set "EXTRACT_DIR=C:\platform-tools"

:: Step 2: Download platform-tools
echo Downloading Android Platform Tools...
powershell -Command "Invoke-WebRequest -Uri '%URL%' -OutFile '%ZIP_FILE%'"

:: Step 3: Extract to C:\platform-tools
echo Extracting to %EXTRACT_DIR%...
powershell -Command "Expand-Archive -Path '%ZIP_FILE%' -DestinationPath 'C:\' -Force"

:: Step 4: Check if path already exists
set "pathEntry=%EXTRACT_DIR%"
set "regPath=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
for /f "tokens=2*" %%a in ('reg query "%regPath%" /v Path ^| findstr /i "Path"') do (
    set "originalPath=%%b"
)

echo Checking if platform-tools is already in PATH...
echo %originalPath% | find /i "%pathEntry%" >nul
if %errorlevel%==0 (
    echo Platform-tools already in PATH.
) else (
    echo Adding platform-tools to system PATH...
    setx /M Path "%originalPath%;%pathEntry%"
)

:: Step 5: Test ADB
echo.
echo Testing ADB...
%EXTRACT_DIR%\adb.exe version

echo.
echo ✅ Done. You may need to restart your command prompt or PC for PATH changes to take effect.
pause
