@echo off
title MINI PROJECT AUTO RUN

REM Go to the folder where this .bat file exists
cd /d "%~dp0"

echo ===============================
echo Starting Blockchain Backend...
echo ===============================
start "Blockchain Backend" cmd /k "cd /d ""%~dp0marine-forensics blockchain\backend"" && node index.js"

timeout /t 6 >nul

echo ===============================
echo Starting AI Backend (Streamlit)...
echo ===============================
start "AI Backend" cmd /k "cd /d ""%~dp0ai-detect-anomalies-navigation"" && python -m streamlit run maritime_cybersecurity_dashboard_updated.py"

timeout /t 5 >nul

echo ===============================
echo Opening Home Page...
echo ===============================
start "" "%~dp0marine-forensics blockchain\frontend\home.html"

echo ===============================
echo Project Started Successfully!
echo ===============================
