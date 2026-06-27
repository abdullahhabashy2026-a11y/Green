$ErrorActionPreference = "Stop"

Get-NetAdapter |
    Where-Object { $_.Status -eq "Up" } |
    ForEach-Object {
        Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses
    }

Write-Host "DNS settings were reset for active network adapters."
