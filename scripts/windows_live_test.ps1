# SPDX-License-Identifier: GPL-3.0-or-later
# Проверка на настоящей Windows (GitHub Actions windows-latest, от имени
# администратора): служба + TUN с настоящим трафиком.
#
#   1. --service-install: настройки, exe и wintun.dll копируются в
#      %ProgramData%\RealityClient; у папки владелец — Администраторы, писать
#      могут только SYSTEM и Администраторы;
#   2. служба поднимает TUN (Wintun) с auto_route: маршруты 0/1 и 128/1 через
#      reality-tun, HTTPS-запрос к сайту идёт через TUN → выход direct (сокет
#      привязан к физическому интерфейсу, без петли), DNS — через DoH;
#   3. тот же сайт через вход mixed (SOCKS5);
#   4. --service-uninstall: служба остановлена штатно, маршруты сняты, сеть
#      работает напрямую.
#
#   pwsh ./scripts/windows_live_test.ps1 -Exe target/release/reality-client.exe
param([Parameter(Mandatory = $true)][string]$Exe)
$ErrorActionPreference = 'Stop'

function Fail($msg) {
    Write-Host "ОШИБКА: $msg"
    $log = Join-Path $env:ProgramData 'RealityClient\reality-client.log'
    if (Test-Path $log) { Write-Host '--- журнал службы ---'; Get-Content $log -Encoding utf8 }
    & $script:exePath --service-uninstall 2>&1 | Out-Host
    exit 1
}

$work = Join-Path $env:RUNNER_TEMP 'rc-live'
if (-not $env:RUNNER_TEMP) { $work = Join-Path $env:TEMP 'rc-live' }
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item (Resolve-Path $Exe) $work -Force
$script:exePath = Join-Path $work 'reality-client.exe'

# Wintun — с официального сайта; подпись DLL (WireGuard LLC) проверяется.
$zip = Join-Path $work 'wintun.zip'
Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
Expand-Archive $zip -DestinationPath (Join-Path $work 'wt') -Force
$dll = Join-Path $work 'wt\wintun\bin\amd64\wintun.dll'
$sig = Get-AuthenticodeSignature $dll
Write-Host "wintun.dll: подпись $($sig.Status), $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'WireGuard LLC') {
    Fail 'подпись wintun.dll не WireGuard LLC'
}
Copy-Item $dll $work -Force

$cfg = @'
{
  "inbounds": [
    { "type": "mixed", "listen": "127.0.0.1", "listen_port": 18090 },
    { "type": "tun", "tag": "tun" }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": {
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" }
    ]
  },
  "dns": { "servers": [{ "type": "https", "tag": "doh", "server": "1.1.1.1", "detour": "direct" }] }
}
'@
$cfgPath = Join-Path $work 'client.json'
[IO.File]::WriteAllText($cfgPath, $cfg, [Text.UTF8Encoding]::new($false))

& $exePath --config $cfgPath --check
if ($LASTEXITCODE) { Fail '--check не прошёл' }

# До установки: адрес сайта и его маршрут.
$site = 'www.example.com'
curl.exe -sS --max-time 20 -o NUL "https://$site/"
if ($LASTEXITCODE) { Fail 'сайт недоступен ещё до запуска клиента — сеть раннера?' }

& $exePath --service-install --config $cfgPath
if ($LASTEXITCODE) { Fail '--service-install' }

$dir = Join-Path $env:ProgramData 'RealityClient'
foreach ($f in 'config.json', 'reality-client.exe', 'wintun.dll') {
    if (-not (Test-Path (Join-Path $dir $f))) { Fail "$f не скопирован в $dir" }
}
$acl = Get-Acl $dir
Write-Host "владелец: $($acl.Owner)"
$acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType, IsInherited -AutoSize | Out-Host
if ($acl.Owner -notmatch 'Administrators|Администраторы') { Fail "владелец папки — $($acl.Owner)" }
if (-not $acl.AreAccessRulesProtected) { Fail 'права папки наследуются сверху' }
$allowed = 'NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|Администраторы'
$others = $acl.Access | Where-Object { $_.IdentityReference.Value -notmatch $allowed }
if ($others) { Fail "в папку есть доступ у: $($others.IdentityReference -join ', ')" }
Write-Host 'OK: папка службы закрыта от пользователей'

$log = Join-Path $dir 'reality-client.log'
function Wait-Tun {
    for ($i = 0; $i -lt 60; $i++) {
        if ((Test-Path $log) -and ((Get-Content $log -Raw -Encoding utf8) -match 'весь трафик направлен в TUN')) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}
if (-not (Wait-Tun)) { Fail 'служба не подняла TUN за 30 с' }

# Подробный журнал для разбора: переменная окружения службы (читается при
# запуске) и перезапуск; заодно проверяется штатная остановка службы.
Stop-Service RealityClient
Remove-Item $log -ErrorAction SilentlyContinue
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\RealityClient' -Name Environment `
    -Type MultiString -Value @('RUST_LOG=debug,netstack_smoltcp=info,smoltcp=info')
Start-Service RealityClient
if (-not (Wait-Tun)) { Fail 'служба после перезапуска не подняла TUN за 30 с' }
Write-Host 'OK: служба остановлена и запущена снова'
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status -AutoSize | Out-Host

$ip = (Resolve-DnsName $site -Type A | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
$route = Find-NetRoute -RemoteIPAddress $ip | Where-Object { $_.InterfaceAlias } | Select-Object -First 1
Write-Host "маршрут к $ip — через $($route.InterfaceAlias)"
if ($route.InterfaceAlias -ne 'reality-tun') { Fail "трафик к $ip идёт не через TUN" }

curl.exe -sS --max-time 30 -o NUL "https://$site/"
if ($LASTEXITCODE) { Fail 'HTTPS через TUN не прошёл' }
Write-Host 'OK: HTTPS через TUN → direct (без петли)'

curl.exe -sS --max-time 30 -o NUL --socks5-hostname 127.0.0.1:18090 "https://$site/"
if ($LASTEXITCODE) { Fail 'HTTPS через SOCKS5-вход не прошёл' }
Write-Host 'OK: HTTPS через вход mixed (SOCKS5)'

& $exePath --service-uninstall
if ($LASTEXITCODE) { Fail '--service-uninstall' }
Start-Sleep -Seconds 2
$text = Get-Content $log -Raw -Encoding utf8
if ($text -notmatch 'завершение по сигналу') { Fail 'служба остановлена не штатно' }
if ($text -notmatch 'маршруты возвращены') { Fail 'маршруты TUN не сняты' }
$route = Find-NetRoute -RemoteIPAddress $ip | Where-Object { $_.InterfaceAlias } | Select-Object -First 1
if ($route.InterfaceAlias -eq 'reality-tun') { Fail 'маршрут через TUN остался' }
curl.exe -sS --max-time 20 -o NUL "https://$site/"
if ($LASTEXITCODE) { Fail 'после удаления службы сеть не работает' }
Write-Host 'OK: служба удалена, маршруты сняты, сеть напрямую'
Write-Host 'WINDOWS LIVE TEST PASSED'
