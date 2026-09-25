# Сборка reality-client на Windows (x86_64, MSVC).
#
# Запуск из корня репозитория в PowerShell:
#   powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
#
# Что нужно заранее (подробно — docs/WINDOWS.md):
#   - Rust через rustup, toolchain stable-x86_64-pc-windows-msvc;
#   - Visual Studio Build Tools с компонентом "Desktop development with C++"
#     (C-компилятор нужен крейту aws-lc-sys — криптографии rustls).
# NASM ставить не обязательно: если его нет, скрипт включает готовые
# объектные файлы из aws-lc-sys (AWS_LC_SYS_PREBUILT_NASM=1).
#
# ВНИМАНИЕ: скрипт написан и проверен по документации и исходникам
# aws-lc-sys, но собрать под Windows из песочницы, где писался проект,
# было невозможно (нет доступа к static.rust-lang.org). Если что-то не
# так — сообщение об ошибке cargo обычно прямо говорит, чего не хватает.

# "Continue", а не "Stop": в Windows PowerShell 5.1 при "Stop" любой вывод
# нативной программы (rustup, cargo) в stderr может считаться ошибкой.
# Успех проверяем явно по $LASTEXITCODE.
$ErrorActionPreference = "Continue"
Set-Location (Join-Path $PSScriptRoot "..")

function Need($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "Не найдено: $cmd. $hint" -ForegroundColor Red
        exit 1
    }
}

Need "cargo" "Установите Rust: https://rustup.rs (toolchain stable-x86_64-pc-windows-msvc)."

$toolchain = ""
if (Get-Command "rustup" -ErrorAction SilentlyContinue) {
    $toolchain = (& rustup show active-toolchain 2>&1 | Out-String).Trim()
}
Write-Host "Rust toolchain: $toolchain"
if ($toolchain -and ($toolchain -notmatch "msvc")) {
    Write-Host "Предупреждение: toolchain не MSVC. Рекомендуется: rustup default stable-x86_64-pc-windows-msvc" -ForegroundColor Yellow
}

if (Get-Command "nasm" -ErrorAction SilentlyContinue) {
    Write-Host "NASM найден — ассемблер aws-lc соберётся из исходников."
} else {
    Write-Host "NASM не найден — используем готовые объекты aws-lc-sys (AWS_LC_SYS_PREBUILT_NASM=1)."
    $env:AWS_LC_SYS_PREBUILT_NASM = "1"
}

cargo build --release -p reality-client
if ($LASTEXITCODE -ne 0) {
    Write-Host "Сборка не удалась. Частая причина — нет Visual Studio Build Tools (C++)." -ForegroundColor Red
    exit $LASTEXITCODE
}

$exe = Join-Path (Get-Location) "target\release\reality-client.exe"
Write-Host ""
Write-Host "Готово: $exe" -ForegroundColor Green
Write-Host "Запуск:"
Write-Host "  & `"$exe`" --server 'vless://...' --listen 127.0.0.1:1080"
Write-Host "Затем укажите SOCKS5-прокси 127.0.0.1:1080 в браузере или программе."
