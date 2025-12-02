@echo off
chcp 65001 >nul
echo =========================================
echo Lambda Deployment Package Builder
echo =========================================
echo.

REM Check if running from correct directory
if not exist "index.py" (
    echo ERROR: index.py not found in current directory
    echo Please run this script from lambda_logs_to_opensearch directory
    pause
    exit /b 1
)

echo Step 1: Creating package directory...
if exist package rmdir /s /q package
mkdir package

echo.
echo Step 2: Installing Python dependencies...
pip install opensearch-py requests-aws4auth boto3 -t package --quiet

if %errorlevel% neq 0 (
    echo ERROR: Failed to install Python packages
    echo Make sure pip is installed and in your PATH
    pause
    exit /b 1
)

echo.
echo Step 3: Copying Lambda function code...
copy index.py package\

echo.
echo Step 4: Creating ZIP file...
cd package
if exist ..\logs_to_opensearch.zip del ..\logs_to_opensearch.zip
powershell -command "Compress-Archive -Path * -DestinationPath ..\logs_to_opensearch.zip -Force"
cd ..

if exist logs_to_opensearch.zip (
    echo.
    echo =========================================
    echo SUCCESS! Deployment package created
    echo =========================================
    echo.
    echo File: logs_to_opensearch.zip
    for %%A in (logs_to_opensearch.zip) do echo Size: %%~zA bytes
    echo.
    echo You can now upload this ZIP file to Lambda console
) else (
    echo ERROR: Failed to create ZIP file
    pause
    exit /b 1
)

echo.
echo Cleaning up...
rmdir /s /q package

echo.
echo =========================================
pause