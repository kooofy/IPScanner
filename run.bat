@echo off
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [初始化] 正在创建虚拟环境...
    python -m venv venv
    if errorlevel 1 (
        echo [错误] 无法创建虚拟环境，请确保已安装 Python 3.10+
        pause
        exit /b 1
    )
    echo [初始化] 正在安装依赖...
    "venv\Scripts\pip.exe" install -r requirements.txt
    if errorlevel 1 (
        echo [错误] 依赖安装失败
        pause
        exit /b 1
    )
    echo [初始化] 完成!
    echo.
)

"venv\Scripts\python.exe" main.py
if errorlevel 1 (
    echo.
    echo [程序异常退出]
    pause
)
