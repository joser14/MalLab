# Manual check of the host network guard (not run by pytest; starts a real Windows Sandbox).
#
#   powershell -ExecutionPolicy Bypass -File tests\manual\verify-host-guard.ps1
#
# Starts a throwaway sandbox WITH networking and NO sample. A probe inside it tries TCP ports on
# this PC (switch address and LAN address), DNS through the host, and the internet, then writes
# the result back. Run it once with the guard off and once with it on (Settings > Host network
# guard). With the guard on, host_*_tcp_open should be empty while dns_via_host and the internet
# checks still succeed. Close nothing yourself: the script tears the sandbox down.

$ErrorActionPreference = "Stop"
$base = Join-Path $env:TEMP ("mallab-guardcheck-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$in = Join-Path $base "in"; $out = Join-Path $base "out"
New-Item -ItemType Directory -Force $in, $out | Out-Null

@'
param([string]$HostLan = "")
$ErrorActionPreference = "SilentlyContinue"
$out = "C:\Users\WDAGUtilityAccount\Desktop\out"
for ($i = 0; $i -lt 30 -and -not (Get-NetRoute -DestinationPrefix '0.0.0.0/0'); $i++) { Start-Sleep 1 }
Start-Sleep 3
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop
function Tcp($h, $p) {
    $c = New-Object Net.Sockets.TcpClient
    try { $t = $c.ConnectAsync($h, $p); $ok = $t.Wait(3000) -and $c.Connected } catch { $ok = $false }
    $c.Close(); return [bool]$ok
}
$r = [ordered]@{ gateway = $gw }
$ports = 135, 139, 445, 2179, 3389, 5040, 5357, 7680, 49664, 49665, 49666, 49667, 49668, 49669
$r.host_switch_tcp_open = @($ports | Where-Object { Tcp $gw $_ })
if ($HostLan) { $r.host_lan_tcp_open = @($ports | Where-Object { Tcp $HostLan $_ }) }
$r.ping_host = [bool](Test-Connection $gw -Count 2 -Quiet)
try { $r.dns_via_host = @(Resolve-DnsName example.com -Server $gw -DnsOnly -Type A -ErrorAction Stop | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress) } catch { $r.dns_via_host = "ERR: " + $_.Exception.Message }
$r.internet_tcp_443 = Tcp "1.1.1.1" 443
try { $r.internet_http = (Invoke-WebRequest "http://example.com" -UseBasicParsing -TimeoutSec 15).StatusCode } catch { $r.internet_http = "ERR: " + $_.Exception.Message }
$r | ConvertTo-Json | Out-File (Join-Path $out "result.json") -Encoding utf8
'@ | Set-Content -Encoding utf8 (Join-Path $in "probe.ps1")

$lan = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.InterfaceAlias -notlike 'vEthernet*' } |
        Select-Object -First 1).IPv4Address.IPAddress
$wsb = Join-Path $base "probe.wsb"
@"
<Configuration>
  <vGPU>Disable</vGPU><Networking>Enable</Networking><ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$in</HostFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$out</HostFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\WDAGUtilityAccount\Desktop\in\probe.ps1 -HostLan $lan</Command></LogonCommand>
</Configuration>
"@ | Set-Content -Encoding utf8 $wsb

$guard = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group 'MalLab host guard' -ErrorAction SilentlyContinue |
           Where-Object { [string]$_.Enabled -eq 'True' }).Count
"Host network guard rules active: $guard of 4. Host LAN address: $lan. Starting the sandbox (takes 1-3 minutes)..."
Start-Process "$env:WINDIR\System32\WindowsSandbox.exe" $wsb
$t = 0
while (-not (Test-Path (Join-Path $out "result.json")) -and $t -lt 360) { Start-Sleep 3; $t += 3 }
Start-Sleep 2
$ErrorActionPreference = "Continue"      # taskkill reports already-gone processes on stderr
foreach ($n in "WindowsSandboxRemoteSession.exe", "WindowsSandboxClient.exe", "WindowsSandbox.exe", "WindowsSandboxServer.exe") {
    taskkill /F /IM $n 2>$null | Out-Null
}
if (Test-Path (Join-Path $out "result.json")) { Get-Content (Join-Path $out "result.json") }
else { "No result after $t s; the sandbox may not have started." }
Start-Sleep 5
Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue
