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
#   4. kill switch (strict_route, фильтры WFP): процесс службы убит —
#      сеть закрыта; служба перезапускается сама — сеть снова через TUN;
#   5. --service-uninstall: служба остановлена штатно, маршруты и kill
#      switch сняты, сеть работает напрямую.
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

function Show-Net {
    Get-NetIPInterface -AddressFamily IPv4 | Format-Table ifIndex, InterfaceAlias, InterfaceMetric, AutomaticMetric, ConnectionState -AutoSize | Out-Host
    Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-Host
}
# Маршрут к адресу. Сразу после появления интерфейса Windows ещё несколько
# секунд его «опознаёт», и Find-NetRoute может ответить «network location
# cannot be reached» — спрашиваем повторно, до 10 с.
function Get-Route($addr) {
    for ($i = 0; $i -lt 20; $i++) {
        $r = $null
        try {
            $r = Find-NetRoute -RemoteIPAddress $addr -ErrorAction Stop |
                Where-Object { $_.InterfaceAlias } | Select-Object -First 1
        } catch { }
        if ($r) { return $r }
        Start-Sleep -Milliseconds 500
    }
    Show-Net
    Fail "за 10 с не нашёлся маршрут к $addr"
}

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
$route = Get-Route $ip
Write-Host "маршрут к $ip — через $($route.InterfaceAlias)"
if ($route.InterfaceAlias -ne 'reality-tun') { Fail "трафик к $ip идёт не через TUN" }

curl.exe -sS --max-time 30 -o NUL "https://$site/"
if ($LASTEXITCODE) { Fail 'HTTPS через TUN не прошёл' }
Write-Host 'OK: HTTPS через TUN → direct (без петли)'

curl.exe -sS --max-time 30 -o NUL --socks5-hostname 127.0.0.1:18090 "https://$site/"
if ($LASTEXITCODE) { Fail 'HTTPS через SOCKS5-вход не прошёл' }
Write-Host 'OK: HTTPS через вход mixed (SOCKS5)'

# Kill switch: та же служба со strict_route.
# Системный DNS через TUN: сразу после включения маршрутов Windows ещё
# несколько секунд «опознаёт» новый интерфейс и шлёт запросы DNS
# физического адаптера — с kill switch они закрыты. Ждём, пока имя
# разрешится (через TUN), и печатаем, сколько на это ушло.
function Wait-Dns {
    $t0 = Get-Date
    for ($i = 0; $i -lt 40; $i++) {
        Clear-DnsClientCache
        $r = Resolve-DnsName $site -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
        if ($r | Where-Object { $_.IPAddress }) {
            Write-Host ("DNS через TUN готов за {0:N1} с" -f ((Get-Date) - $t0).TotalSeconds)
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Tun-Count {
    if (-not (Test-Path $log)) { return 0 }
    return @(Select-String -Path $log -Pattern 'весь трафик направлен в TUN' -Encoding utf8).Count
}
Stop-Service RealityClient
Remove-Item $log -ErrorAction SilentlyContinue
$strict = $cfg -replace '\{ "type": "tun", "tag": "tun" \}', '{ "type": "tun", "tag": "tun", "strict_route": true }'
if ($strict -eq $cfg) { Fail 'не удалось включить strict_route в настройках теста' }
[IO.File]::WriteAllText($cfgPath, $strict, [Text.UTF8Encoding]::new($false))
& $exePath --service-install --config $cfgPath
if ($LASTEXITCODE) { Fail '--service-install со strict_route' }
if (-not (Wait-Tun)) { Fail 'служба со strict_route не подняла TUN за 30 с' }
if ((Get-Content $log -Raw -Encoding utf8) -notmatch 'kill switch включён') { Fail 'kill switch не включился' }
if (-not (Wait-Dns)) { Show-Net; Fail 'со strict_route системный DNS не заработал за 20 с' }
curl.exe -sS --max-time 30 -o NUL "https://$site/"
if ($LASTEXITCODE) { Show-Net; Fail 'HTTPS через TUN со strict_route не прошёл' }
Write-Host 'OK: kill switch включён, трафик идёт через TUN'

# Один владелец auto_route: --tun-cleanup не снимает фильтры работающей службы.
$out = & $exePath --tun-cleanup 2>&1 | Out-String
if (-not $LASTEXITCODE) { Fail '--tun-cleanup снял kill switch работающей службы' }
if ($out -notmatch 'уже держит другой') { Write-Host $out; Fail '--tun-cleanup: нет сообщения о занятом auto_route' }
curl.exe -sS --max-time 30 -o NUL "https://$site/"
if ($LASTEXITCODE) { Show-Net; Fail 'после отказа --tun-cleanup HTTPS через TUN не прошёл' }
Write-Host 'OK: --tun-cleanup не тронул работающую службу'

# Сбой: процесс убит, интерфейс TUN исчез — мимо туннеля трафик не идёт.
Stop-Process -Name reality-client -Force
Start-Sleep -Milliseconds 500
curl.exe -sS --max-time 4 -o NUL "https://$ip/" -k
if (-not $LASTEXITCODE) { Fail 'kill switch: клиент убит, а трафик пошёл мимо туннеля' }
Write-Host 'OK: клиент убит — сеть закрыта (kill switch)'

# Служба перезапускается сама (через 5 с) и снова пускает трафик.
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
    if ((Tun-Count) -ge 2) { $ok = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $ok) { Fail 'служба не перезапустилась после сбоя за 30 с' }
if (-not (Wait-Dns)) { Show-Net; Fail 'после перезапуска системный DNS не заработал за 20 с' }
curl.exe -sS --max-time 30 -o NUL "https://$site/"
if ($LASTEXITCODE) { Show-Net; Fail 'после перезапуска службы HTTPS через TUN не прошёл' }
Write-Host 'OK: служба перезапустилась, трафик снова через TUN'

& $exePath --service-uninstall
if ($LASTEXITCODE) { Fail '--service-uninstall' }
Start-Sleep -Seconds 2
$text = Get-Content $log -Raw -Encoding utf8
if ($text -notmatch 'завершение по сигналу') { Fail 'служба остановлена не штатно' }
if ($text -notmatch 'маршруты возвращены') { Fail 'маршруты TUN не сняты' }
if ($text -notmatch 'kill switch снят') { Fail 'kill switch не снят при штатной остановке' }
$route = Get-Route $ip
if ($route.InterfaceAlias -eq 'reality-tun') { Fail 'маршрут через TUN остался' }
curl.exe -sS --max-time 20 -o NUL "https://$site/"
if ($LASTEXITCODE) { Fail 'после удаления службы сеть не работает' }
Write-Host 'OK: служба удалена, маршруты и kill switch сняты, сеть напрямую'
& $exePath --tun-cleanup
if ($LASTEXITCODE) { Fail '--tun-cleanup (снимать уже нечего) завершился с ошибкой' }
Write-Host 'OK: --tun-cleanup'
Write-Host 'WINDOWS LIVE TEST PASSED'
