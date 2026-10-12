@echo off
setlocal

echo ============================================
echo  ShadowAgent one-click start/stop
echo  Services running  -^> stop them
echo  Not running       -^> start them
echo ============================================

powershell -NoProfile -Command "$p = Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('node.exe','python.exe') -and ($_.CommandLine -match 'ShadowAgent' -or $_.CommandLine -match 'uvicorn') }; $w = Get-Process | Where-Object { $_.MainWindowTitle -like 'Frontend*' -or $_.MainWindowTitle -like 'Backend*' -or $_.MainWindowTitle -like 'next-server*' }; if ($p -or $w) { exit 0 } else { exit 1 }"

if %errorlevel% equ 0 (
    echo [MODE] Services detected - shutting down...
    powershell -NoProfile -Command "Get-Process | Where-Object { $_.MainWindowTitle -like 'Frontend*' -or $_.MainWindowTitle -like 'Backend*' -or $_.MainWindowTitle -like 'next-server*' } | ForEach-Object { taskkill /f /t /pid $_.Id | Out-Null }"
    powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('node.exe','python.exe') -and ($_.CommandLine -match 'ShadowAgent' -or $_.CommandLine -match 'uvicorn') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
    echo [DONE] ShadowAgent services stopped.
    echo [EXIT] Auto-closing this window...
    exit
) else (
    echo [MODE] No services running - starting up...
    start "" /min cmd /k "title Frontend && cd /d D:\02_Projects\Github_projects\ShadowAgent\frontend && npm run dev"
    start "" /min cmd /k "title Backend && cd /d D:\02_Projects\Github_projects\ShadowAgent\backend && python -m uvicorn main:app --reload"
    echo [DONE] Frontend + Backend started, windows minimized to taskbar.
    exit
)
