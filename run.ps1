$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "[初始化] 正在创建虚拟环境..."
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] 无法创建虚拟环境，请确保已安装 Python 3.10+"
        pause
        exit 1
    }
    Write-Host "[初始化] 正在安装依赖..."
    & "venv\Scripts\pip.exe" install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[错误] 依赖安装失败"
        pause
        exit 1
    }
    Write-Host "[初始化] 完成!`n"
}

& "venv\Scripts\python.exe" main.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[程序异常退出]"
    pause
}
