@echo off
REM ============================================================
REM  MalLab - standalone malware research lab
REM  Starts the lab server and opens it in your browser.
REM  Lab data (cases, quarantine, reports, YARA rules, tools)
REM  lives in .\lab ; leave this window open while you work.
REM ============================================================
setlocal
cd /d "%~dp0"
echo Starting MalLab...  (lab data: %~dp0lab)
echo Close this window to stop the lab.
python server.py --lab-root "%~dp0lab" %*
endlocal
