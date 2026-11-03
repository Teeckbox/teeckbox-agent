<#
.SYNOPSIS
    Installs the Teeckbox agent as a Windows service that runs under its own virtual account.

.DESCRIPTION
    Run it from an elevated PowerShell. It creates the folders, registers the service "TeeckboxAgent" (started automatically, restarted
    if it stops) under the virtual account "NT SERVICE\TeeckboxAgent", which has no password and no rights besides the ones given to it.
    It does not start the service: enrol the agent first, with the account granted access to the keys:

        teeckbox-agent.exe enroll --url https://teeckbox.example.com --code tbe_... --grant "NT SERVICE\TeeckboxAgent"

    then list the destinations the agent may call in agent.yaml, and start the service (Start-Service TeeckboxAgent).

.PARAMETER ExePath
    The teeckbox-agent.exe to run as the service. Default: the one next to this script, or in the current folder.

.PARAMETER ConfigPath
    The agent.yaml. Default: %ProgramData%\Teeckbox\Agent\agent.yaml.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $ExePath = (Join-Path (Get-Location) 'teeckbox-agent.exe'),
    [string] $ConfigPath = (Join-Path $env:ProgramData 'Teeckbox\Agent\agent.yaml')
)

$ErrorActionPreference = 'Stop'
$name = 'TeeckboxAgent'
$account = "NT SERVICE\$name"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (as administrator).'
}
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "teeckbox-agent.exe was not found at $ExePath. Give its path with -ExePath."
}
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    throw "The service $name already exists. Stop and remove it first (sc.exe delete $name) to install it again."
}

$exe = (Resolve-Path -LiteralPath $ExePath).Path
$config = [IO.Path]::GetFullPath($ConfigPath)
$folder = Split-Path -Parent $config
$data = Join-Path $folder 'data'

if ($PSCmdlet.ShouldProcess($name, "Install the service for $exe")) {
    New-Item -ItemType Directory -Force -Path $folder, $data | Out-Null

    # The service starts agent.yaml's agent: its own command line, no secret in it.
    $binary = "`"$exe`" run --config `"$config`" --data-folder `"$data`""
    New-Service -Name $name -DisplayName 'Teeckbox Agent' -BinaryPathName $binary -StartupType Automatic `
        -Description 'Makes the calls of Teeckbox to the systems of this network. No inbound port.' | Out-Null

    # A virtual account: no password to manage, no rights beyond the ones granted explicitly.
    sc.exe config $name obj= $account | Out-Null
    sc.exe sidtype $name unrestricted | Out-Null
    # Restart after a failure: after 5 s, then 30 s, then a minute; the counter resets after a day.
    sc.exe failure $name reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null

    # The configuration is read by the service, never written by it: the account may read the folder, and the allow list stays an
    # administrator's decision.
    icacls $folder /grant "${account}:(OI)(CI)RX" | Out-Null
    icacls $data /grant "${account}:(OI)(CI)M" | Out-Null

    Write-Host "Service $name installed (account $account)."
    Write-Host "Next: enrol the agent with --grant `"$account`", write the allow list in $config, then Start-Service $name."
}
