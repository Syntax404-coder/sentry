# SENTRY - Advanced Process Monitoring & Management Tool
# Submitted by: Domenic R. Taganahan

# --- GLOBAL SETTINGS ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- NATIVE METHODS (P/INVOKE) ---
$MethodDefinition = @'
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr processHandle);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr processHandle);
'@
if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {
    Add-Type -MemberDefinition $MethodDefinition -Name 'NativeMethods' -Namespace 'Win32'
}

# --- THEME CONFIGURATION ---
$Hex = @{
    BrightGreen = "38;2;20;148;20"   
    DarkGreen   = "38;2;14;107;14"   
    SageGreen   = "38;2;100;149;104" 
    LightGreen  = "38;2;156;204;156" 
    OliveGreen  = "38;2;43;83;41"    
    Red         = "38;2;200;50;50"   
    Blue        = "38;2;80;160;220"  
    Yellow      = "38;2;220;220;80"  
    Reset       = "0"
}

$LogFile = "$PSScriptRoot\sentry_activity_log.json"

# --- UI UTILITIES ---

function Color-Text {
    param($Text, $ColorCode)
    $Esc = [char]27
    return "$Esc[$($ColorCode)m$Text$Esc[0m"
}

function Get-WindowWidth {
    try { return $Host.UI.RawUI.WindowSize.Width } catch { return 120 }
}

function Center-Block {
    param($Lines)
    $maxWidth = ($Lines | Measure-Object -Property Length -Maximum).Maximum
    $windowWidth = Get-WindowWidth
    $padLength = [math]::Max(0, [math]::Floor(($windowWidth - $maxWidth) / 2))
    $padding = " " * $padLength
    
    foreach ($line in $Lines) {
        Write-Host "$padding$line"
    }
}

function Show-Header {
    $content = @(
        "                                                                        ",
        "      ::::::::  :::::::::: ::::    ::: ::::::::::: :::::::::  :::    ::: ",
        "     :+:    :+: :+:        :+:+:   :+:     :+:     :+:    :+: :+:    :+: ",
        "    +:+        +:+        :+:+:+  +:+     +:+     +:+    +:+  +:+ +:+    ",
        "   +#++:++#++ +#++:++#   +#+ +:+ +#+     +#+     +#++:++#:    +#++:      ",
        "          +#+ +#+        +#+  +#+#+#     +#+     +#+    +#+    +#+       ",
        "  #+#    #+# #+#        #+#   #+#+#     #+#     #+#    #+#    #+#        ",
        "  ########  ########## ###    ####     ###     ###    ###    ###         ",
        "                                                                        ",
        "                  Secure. Central. Superior.                            ",
        "                       Activity Tracker                                 " 
    )

    $maxWidth = ($content | Measure-Object -Property Length -Maximum).Maximum
    $graphic = @()
    
    $borderLine = "+" + ("-" * ($maxWidth + 2)) + "+"
    $graphic += Color-Text -Text $borderLine -ColorCode $Hex.DarkGreen
    
    foreach ($line in $content) {
        if ($line -match "Secure" -or $line -match "Activity") {
            $coloredLine = Color-Text -Text $line.PadRight($maxWidth) -ColorCode $Hex.LightGreen
        } else {
            $coloredLine = Color-Text -Text $line.PadRight($maxWidth) -ColorCode $Hex.BrightGreen
        }
        $side = Color-Text -Text "|" -ColorCode $Hex.DarkGreen
        $graphic += "$side $coloredLine $side"
    }
    
    $graphic += Color-Text -Text $borderLine -ColorCode $Hex.DarkGreen

    $windowWidth = Get-WindowWidth
    foreach ($line in $graphic) {
        $visibleLength = $maxWidth + 4 
        $padLength = [math]::Max(0, [math]::Floor(($windowWidth - $visibleLength) / 2))
        Write-Host (" " * $padLength) -NoNewline
        Write-Host $line 
    }
    Write-Host "`n"
}

function Get-SafeInput {
    Param([string]$Prompt, [int]$MaxLength = 6)
    $windowWidth = Get-WindowWidth
    $cleanPrompt = "$Prompt > "
    $padLength = [math]::Max(0, [math]::Floor(($windowWidth - $cleanPrompt.Length) / 2))
    $padding = " " * $padLength

    Write-Host $padding -NoNewline
    Write-Host $(Color-Text -Text $cleanPrompt -ColorCode $Hex.LightGreen) -NoNewline
    
    $rawInput = Read-Host
    if ($null -eq $rawInput) { return "" }
    $cleanInput = $rawInput.Trim()

    if ($cleanInput.Length -gt $MaxLength) {
        Write-Host "`n[!] WARNING: Input too long." -ForegroundColor Red
        return $null
    }
    return $cleanInput
}

function Draw-Bar {
    param ($Label, $Value, $Max, $Width=20, $Unit="")
    if ($Max -eq 0) { $Max = 1 }
    $ratio = $Value / $Max
    $fillCount = [math]::Min($Width, [math]::Max(0, [math]::Round($ratio * $Width)))
    $emptyCount = $Width - $fillCount
    $BlockFull  = [char]0x2588 
    $BlockEmpty = [char]0x2591 
    $filled = "$BlockFull" * $fillCount
    $empty  = "$BlockEmpty" * $emptyCount
    $barArt = "$(Color-Text $filled $Hex.BrightGreen)$(Color-Text $empty $Hex.DarkGreen)"
    $valStr = Color-Text "$Value$Unit" $Hex.SageGreen
    $lblStr = Color-Text $Label.PadRight(20) $Hex.LightGreen
    return "$lblStr | $barArt $valStr"
}

# --- SYSTEM MANAGEMENT FUNCTIONS ---

function Manage-Process {
    Param([string]$PreSelectedTarget = $null) 

    $inProcMenu = $true
    $directJump = if ($PreSelectedTarget) { $true } else { $false }

    do {
        if (-not $directJump) {
            Clear-Host
            Show-Header
            Write-Host "`n$(Color-Text '[DEEP PROCESS CONTROL]' $Hex.BrightGreen)"
            
            Write-Host "Select View Mode:"
            Write-Host " [1] " -NoNewline -ForegroundColor Green
            Write-Host "User Apps Only (Safe Mode)" -ForegroundColor Gray
            Write-Host " [2] " -NoNewline -ForegroundColor Red
            Write-Host "Show Everything (God Mode)" -ForegroundColor Gray
            Write-Host " [B] " -NoNewline -ForegroundColor Yellow
            Write-Host "Back to Main Menu" -ForegroundColor Gray
            
            $filterMode = Get-SafeInput -Prompt "Choice" -MaxLength 1
            
            if ($filterMode -eq 'B' -or $filterMode -eq 'Q') { $inProcMenu = $false; return }

            $CriticalSystem = @(
                "Idle", "System", "svchost", "csrss", "wininit", "winlogon", 
                "services", "lsass", "smss", "registry", "StandardCollector.Service", 
                "Memory Compression", "spoolsv", "explorer", "taskmgr", "MsMpEng",
                "RuntimeBroker", "SearchIndexer", "ApplicationFrameHost", "TextInputHost"
            )

            $procs = Get-Process | Where-Object { $_.Id -ne $PID }

            if ($filterMode -eq '2') {
                Write-Host "$(Color-Text 'Scanning ALL processes...' $Hex.Red)"
                $hogs = $procs | Sort-Object CPU -Descending | Select-Object -First 10
            } else {
                Write-Host "$(Color-Text 'Scanning USER applications...' $Hex.SageGreen)"
                $hogs = $procs | Where-Object { 
                    $_.ProcessName -notin $CriticalSystem -and 
                    $_.Path -notmatch "Windows\\System32" 
                } | Sort-Object CPU -Descending | Select-Object -First 10
            }
            
            $menuLines = @()
            $bL = Color-Text "[" $Hex.OliveGreen
            $bR = Color-Text "]" $Hex.OliveGreen
            $i = 1

            if ($hogs.Count -eq 0) { Write-Host "No relevant processes found." -ForegroundColor Gray; return }

            foreach ($hog in $hogs) {
                $num = "$bL " + $(Color-Text "$i" $Hex.LightGreen) + " $bR"
                $name = Color-Text $hog.ProcessName.PadRight(25) $Hex.SageGreen
                $pidTxt = Color-Text "(PID: $($hog.Id))" $Hex.DarkGreen
                $cpuTxt = Color-Text "CPU: $([math]::Round($hog.CPU, 0))s" $Hex.OliveGreen
                $menuLines += "$num $name $pidTxt $cpuTxt"
                $i++
            }
            
            Center-Block -Lines $menuLines
            Write-Host "`n$(Color-Text 'SELECT A TARGET:' $Hex.LightGreen)"
            $selection = Get-SafeInput -Prompt "Enter Number (1-10) or AppName (or 'B' to back)" -MaxLength 30
            
            if ($selection -eq 'B' -or [string]::IsNullOrWhiteSpace($selection)) { continue }
        } else {
            $selection = $PreSelectedTarget
        }

        # RESOLVE TARGET
        $target = $null
        
        if ($directJump) {
            if ($selection -match "^\d+$") {
                $target = Get-Process -Id $selection -ErrorAction SilentlyContinue
            }
        } 
        elseif ($selection -match "^\d+$" -and $selection -le 10) {
            $target = $hogs[[int]$selection - 1]
        } elseif ($selection -match "^[a-zA-Z]") {
            # --- NAME BASED KILL WITH WARNING (Main Menu) ---
            $appName = $selection
            if ($appName -notlike "*.exe") { $appName = "$appName.exe" }
            
            Clear-Host
            Show-Header
            Write-Host "`n$(Color-Text '!!! CRITICAL WARNING !!!' $Hex.Red)"
            Write-Host "You are about to force-kill the ENTIRE application tree for:"
            Write-Host "$(Color-Text $appName $Hex.Yellow)"
            Write-Host "`nThis will close ALL windows/tabs associated with this application."
            
            $confirm = Get-SafeInput -Prompt "Type 'YES' to confirm" -MaxLength 3
            if ($confirm -eq 'YES') {
                Write-Host "`n$(Color-Text 'Executing TaskKill...' $Hex.Red)"
                taskkill /F /IM $appName /T
                Start-Sleep -Seconds 2
            } else {
                Write-Host "Cancelled." -ForegroundColor Green; Start-Sleep -Seconds 1
            }
            continue
        }

        if ($null -eq $target) { 
            Write-Host "Invalid target or Process not found." -ForegroundColor Red; 
            Start-Sleep -Seconds 1; 
            if ($directJump) { return } else { continue }
        }

        # --- ACTION SUB-MENU ---
        Clear-Host
        Show-Header
        Write-Host "$(Color-Text "MANAGING: $($target.ProcessName) (PID: $($target.Id))" $Hex.Yellow)"
        Write-Host "------------------------------------------------"
        Write-Host "[ 1 ] KILL PROCESS (Tree Terminate)"
        Write-Host "[ 2 ] FREEZE / RESUME (Suspend in Memory)"
        Write-Host "[ 3 ] SET PRIORITY (RealTime/High/Normal/Idle)"
        Write-Host "[ 4 ] SET AFFINITY (Core Latching)"
        Write-Host "[ B ] Back to List"
        Write-Host "------------------------------------------------"
        
        $action = Get-SafeInput -Prompt "Action" -MaxLength 1

        switch ($action) {
            '1' { 
                # --- UPDATED: WARNING SCREEN FOR PID KILL ---
                Clear-Host
                Show-Header
                Write-Host "`n$(Color-Text '!!! CRITICAL WARNING !!!' $Hex.Red)"
                Write-Host "You are about to force-kill the ENTIRE application tree for:"
                Write-Host "$(Color-Text $target.ProcessName $Hex.Yellow) (PID: $($target.Id))"
                Write-Host "`nThis will close ALL windows/tabs associated with this application."
                
                $confirm = Get-SafeInput -Prompt "Type 'YES' to confirm" -MaxLength 3
                
                if ($confirm -eq 'YES') {
                    Write-Host "`n$(Color-Text 'Nuking process tree...' $Hex.Red)"
                    
                    # Smart Kill: Use Name to get the whole tree (avoids just crashing one tab)
                    $procName = $target.ProcessName
                    if ($procName -notlike "*.exe") { $procName = "$procName.exe" }
                    
                    # Suppress output to keep UI clean, check exit code
                    $null = taskkill /F /IM $procName /T 
                    
                    Write-Host "$(Color-Text 'Target Neutralized.' $Hex.LightGreen)"
                } else {
                    Write-Host "$(Color-Text 'Action Cancelled.' $Hex.SageGreen)"
                }
                Start-Sleep -Seconds 2
                if ($directJump) { return }
            }
            '2' {
                Write-Host "1. FREEZE (Suspend)`n2. UNFREEZE (Resume)"
                $frz = Get-SafeInput -Prompt "Choice" -MaxLength 1
                if ($frz -eq '1') {
                    [Win32.NativeMethods]::NtSuspendProcess($target.Handle)
                    Write-Host "$(Color-Text 'Process Frozen.' $Hex.Blue)"
                } elseif ($frz -eq '2') {
                    [Win32.NativeMethods]::NtResumeProcess($target.Handle)
                    Write-Host "$(Color-Text 'Process Resumed.' $Hex.LightGreen)"
                }
                Read-Host "Press Enter..."
            }
            '3' {
                Write-Host "Levels: (I)dle, (N)ormal, (H)igh, (R)ealTime"
                $prio = Get-SafeInput -Prompt "Level" -MaxLength 1
                try {
                    if ($prio -eq 'R') { $target.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::RealTime }
                    elseif ($prio -eq 'H') { $target.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High }
                    elseif ($prio -eq 'N') { $target.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Normal }
                    elseif ($prio -eq 'I') { $target.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle }
                    Write-Host "Priority Updated."
                } catch { Write-Host "Access Denied." -ForegroundColor Red }
                Read-Host "Press Enter..."
            }
            '4' {
                $cores = $env:NUMBER_OF_PROCESSORS
                Write-Host "Available Cores: 0 to $($cores - 1)"
                $inputCores = Get-SafeInput -Prompt "Enter Cores (e.g. 0,2,3)" -MaxLength 10
                try {
                    $bitmask = 0
                    $inputCores.Split(',') | ForEach-Object { $bitmask += [math]::Pow(2, [int]$_) }
                    $target.ProcessorAffinity = $bitmask
                    Write-Host "Affinity Set."
                } catch { Write-Host "Invalid Core Selection." -ForegroundColor Red }
                Read-Host "Press Enter..."
            }
            'B' {
                if ($directJump) { return }
            }
        }
    } while ($inProcMenu -and -not $directJump)
}

# --- SYSTEM MONITORING FUNCTIONS ---

function Get-ResourceHogs {
    Param([string]$Type)
    
    $pageSize = 10
    $pageIndex = 0
    $browsing = $true

    Write-Host "`nScanning top 30 processes..." -ForegroundColor DarkGray
    if ($Type -eq "Memory") {
        $rawHogs = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 30
        $maxVal = if ($rawHogs) { [math]::Round($rawHogs[0].WorkingSet / 1MB, 2) } else { 100 }
        $unit = " MB"
    }
    elseif ($Type -eq "CPU") {
        $rawHogs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 30
        $maxVal = if ($rawHogs) { [math]::Round($rawHogs[0].CPU, 2) } else { 100 }
        $unit = " s"
    }

    if ($null -eq $rawHogs -or $rawHogs.Count -eq 0) {
        Write-Host "No data available." -ForegroundColor Red; Start-Sleep 2; return
    }

    while ($browsing) {
        Clear-Host
        Show-Header
        
        $totalPages = [math]::Ceiling($rawHogs.Count / $pageSize)
        $displayPage = $pageIndex + 1
        
        Write-Host "`n$(Color-Text "[ TOP 30 $Type HOGS - PAGE $displayPage OF $totalPages ]" $Hex.BrightGreen)" 
        
        $pagedData = $rawHogs | Select-Object -Skip ($pageIndex * $pageSize) -First $pageSize
        
        $lines = @()
        
        $counter = ($pageIndex * $pageSize) + 1
        $bL = Color-Text "[" $Hex.OliveGreen
        $bR = Color-Text "]" $Hex.OliveGreen

        foreach ($h in $pagedData) {
            if ($Type -eq "Memory") { $val = [math]::Round($h.WorkingSet / 1MB, 2) }
            else { $val = [math]::Round($h.CPU, 2) }
            
            $numStr = "$bL " + $(Color-Text "$counter" $Hex.LightGreen) + " $bR"
            if ($counter -lt 10) { $numStr += " " }
            
            $barOnly = Draw-Bar -Label "" -Value $val -Max $maxVal -Width 20 -Unit $unit
            $row = "$numStr $(Color-Text $h.ProcessName.PadRight(20) $Hex.SageGreen) $barOnly"
            $lines += $row
            $counter++
        }
        
        Center-Block -Lines $lines
        
        Write-Host "`n$(Color-Text 'NAVIGATION:' $Hex.LightGreen)"
        
        if ($displayPage -lt $totalPages) { Write-Host " [ N ] Next" -NoNewline -ForegroundColor Cyan }
        if ($displayPage -gt 1) { Write-Host "   [ P ] Prev" -NoNewline -ForegroundColor Cyan }
        Write-Host "   [ M ] Manage Process" -NoNewline -ForegroundColor Red
        Write-Host "   [ B ] Back" -ForegroundColor Yellow
        
        $nav = Get-SafeInput -Prompt "Action" -MaxLength 2 
        
        if ($nav -eq 'N' -and $displayPage -lt $totalPages) {
            $pageIndex++
        }
        elseif ($nav -eq 'P' -and $displayPage -gt 1) {
            $pageIndex--
        }
        elseif ($nav -eq 'M') {
            $numSelect = Get-SafeInput -Prompt "Enter List Number (1-$($rawHogs.Count))" -MaxLength 3
            if ($numSelect -match "^\d+$") {
                $idx = [int]$numSelect - 1
                if ($idx -ge 0 -and $idx -lt $rawHogs.Count) {
                    $selectedPID = $rawHogs[$idx].Id
                    Manage-Process -PreSelectedTarget $selectedPID
                } else {
                    Write-Host "Number out of range." -ForegroundColor Red; Start-Sleep 1
                }
            }
        }
        elseif ($nav -eq 'B' -or $nav -eq 'Q') {
            $browsing = $false
        }
    }
}

function Get-NetworkProcs {
    Write-Host "`n$(Color-Text '[ACTIVE TRAFFIC SCANNER]' $Hex.BrightGreen)"
    Write-Host "$(Color-Text 'Filtering relevant external connections...' $Hex.SageGreen)"
    
    $outputLines = @()
    
    $tcp = Get-NetTCPConnection -State Established | Where-Object { 
        $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" -and
        $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" -and
        $_.RemoteAddress -ne "0.0.0.0"
    } | Select-Object @{N='Type';E={'TCP'}}, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $udp = Get-NetUDPEndpoint | Where-Object {
        $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1"
    } | Select-Object @{N='Type';E={'UDP'}}, LocalAddress, LocalPort, @{N='RemoteAddress';E={'*'}}, @{N='RemotePort';E={'*'}}, @{N='State';E={'Open'}}, OwningProcess

    $allNet = $tcp + $udp
    
    $hProto  = Color-Text "PROTO" $Hex.LightGreen
    $hRemote = Color-Text "REMOTE IP:PORT".PadRight(22) $Hex.LightGreen
    $hState  = Color-Text "STATE".PadRight(12) $Hex.LightGreen
    $hProc   = Color-Text "PROCESS (PID)" $Hex.LightGreen
    
    $outputLines += "$hProto | $hRemote | $hState | $hProc"
    $outputLines += Color-Text ("-" * 70) $Hex.DarkGreen
    
    $count = 0
    foreach ($conn in $allNet) {
        if ($count -ge 20) { break }
        $procName = "Unknown"
        try { 
            $p = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($p) { $procName = $p.ProcessName }
        } catch {}

        if ($procName -eq "svchost" -or $procName -eq "System") { continue }

        if ($conn.Type -eq "TCP") { $cType = Color-Text "TCP " $Hex.Blue }
        else { $cType = Color-Text "UDP " $Hex.Yellow }
        
        $cRemote = Color-Text "$($conn.RemoteAddress):$($conn.RemotePort)".PadRight(22) $Hex.SageGreen
        $cState  = Color-Text "$($conn.State)".PadRight(12) $Hex.OliveGreen
        $cProc   = Color-Text "$procName ($($conn.OwningProcess))" $Hex.BrightGreen
        
        $outputLines += "$cType | $cRemote | $cState | $cProc"
        $count++
    }
    
    if ($outputLines.Count -gt 2) {
        Center-Block -Lines $outputLines
        if ($count -ge 20) { Write-Host "`n(List truncated to top 20 relevant active connections)" -ForegroundColor Gray }
    } else {
        Write-Host "No active external connections found." -ForegroundColor Gray
    }
}

function Analyze-ShadyProcs {
    Write-Host "`n$(Color-Text '[SHADY PROCESS SCANNER]' $Hex.BrightGreen)"
    Write-Host "$(Color-Text 'Scanning running processes & heuristics...' $Hex.SageGreen)"
    $procs = Get-Process
    $suspicious = @()
    foreach ($p in $procs) {
        if ($p.Id -eq 0 -or [string]::IsNullOrEmpty($p.Path)) { continue }
        $reason = ""
        if ($p.Path -match "AppData" -or $p.Path -match "Temp") { $reason += "[Suspicious Path] " }
        if ($p.Path -notmatch "Windows\\System32") {
             try { $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue; if ($sig.Status -ne "Valid") { $reason += "[Unsigned] " } } catch {}
        }
        if ($p.ProcessName -eq "powershell" -and $p.MainWindowTitle -eq "") {
             $reason += "[Hidden PowerShell] "
        }
        if ($reason) { $suspicious += [PSCustomObject]@{ PID=$p.Id; Name=$p.ProcessName; Reason=$reason; Path=$p.Path } }
    }
    if ($suspicious.Count -gt 0) { $suspicious | Format-Table -AutoSize | Out-Host -Paging } else { Write-Host "$(Color-Text 'No obvious shady processes found.' $Hex.LightGreen)" }
}

function Manage-StartupApps {
    $inStartupMenu = $true
    do {
        Clear-Host
        Show-Header
        Write-Host "`n$(Color-Text '[STARTUP APP MANAGER]' $Hex.BrightGreen)"
        
        try {
            $bootEvent = Get-WinEvent -LogName "Microsoft-Windows-Diagnostics-Performance/Operational" -MaxEvents 1 -FilterXPath "*[System[(EventID=100)]]" -ErrorAction SilentlyContinue
            if ($bootEvent) {
                $bootSeconds = [math]::Round($bootEvent.Properties[0].Value / 1000, 2)
                Write-Host "Last BIOS Boot Time: " -NoNewline -ForegroundColor Gray
                Write-Host "$bootSeconds s" -ForegroundColor Cyan
            } else {
                 Write-Host "Last BIOS Boot Time: N/A (Requires Admin or no Event Data)" -ForegroundColor Gray
            }
        } catch {}

        Write-Host "`nScanning Registry for Startup Apps..." -ForegroundColor DarkGray
        
        $startupApps = @()
        
        try {
            $hkcu = Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue
            foreach ($p in $hkcu.PSObject.Properties) {
                if ($p.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $startupApps += [PSCustomObject]@{ Name=$p.Name; Path=$p.Value; Hive="CurrentUser" }
                }
            }
        } catch {}
        
        try {
            $hklm = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue
            foreach ($p in $hklm.PSObject.Properties) {
                if ($p.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $startupApps += [PSCustomObject]@{ Name=$p.Name; Path=$p.Value; Hive="LocalMachine" }
                }
            }
        } catch {}

        $i = 1
        $bL = Color-Text "[" $Hex.OliveGreen
        $bR = Color-Text "]" $Hex.OliveGreen
        
        if ($startupApps.Count -gt 0) {
            foreach ($app in $startupApps) {
                $idx = "$bL " + $(Color-Text "$i" $Hex.LightGreen) + " $bR"
                $appName = Color-Text $app.Name.PadRight(25) $Hex.SageGreen
                $hive = Color-Text "[$($app.Hive)]" $Hex.Blue
                
                $cleanPath = $app.Path
                if ($cleanPath.Length -gt 50) { $cleanPath = $cleanPath.Substring(0, 47) + "..." }
                $pathTxt = Color-Text $cleanPath $Hex.OliveGreen
                
                Write-Host "$idx $appName $hive $pathTxt"
                $i++
            }
        } else {
            Write-Host "No registry startup apps found." -ForegroundColor Yellow
        }

        Write-Host "`n$(Color-Text 'OPTIONS:' $Hex.LightGreen)"
        Write-Host "1. Type a $(Color-Text 'Number' $Hex.BrightGreen) to REMOVE that app."
        Write-Host "2. Type $(Color-Text 'B' $Hex.Yellow) to Back to Main Menu."

        $choice = Get-SafeInput -Prompt "Selection" -MaxLength 2

        if ($choice -eq 'B' -or $choice -eq 'Q') { $inStartupMenu = $false; return }

        if ($choice -match "^\d+$") {
            $selInt = [int]$choice
            if ($selInt -gt 0 -and $selInt -le $startupApps.Count) {
                $target = $startupApps[$selInt - 1]
                Write-Host "`nAre you sure you want to REMOVE: $($target.Name)?" -ForegroundColor Red
                $confirm = Get-SafeInput -Prompt "Type YES to confirm" -MaxLength 3
                
                if ($confirm -eq "YES") {
                    try {
                        if ($target.Hive -eq "CurrentUser") {
                            Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name $target.Name -ErrorAction Stop
                        } else {
                            Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -Name $target.Name -ErrorAction Stop
                        }
                        Write-Host "Successfully Removed." -ForegroundColor Green
                        Start-Sleep -Seconds 1
                    } catch {
                        Write-Host "Failed to remove. Access Denied (Run as Admin)." -ForegroundColor Red
                        Start-Sleep -Seconds 2
                    }
                }
            }
        }
    } while ($inStartupMenu)
}

# --- DATA & LOGGING FUNCTIONS ---

function Update-ActivityLog {
    Write-Host "`n$(Color-Text '[ACTIVITY LOGGER]' $Hex.BrightGreen)"
    Write-Host "$(Color-Text 'Snapshotting active process durations...' $Hex.SageGreen)"
    $now = Get-Date
    $procs = Get-Process | Where-Object { $_.StartTime -ne $null }
    $newData = @()
    foreach ($p in $procs) {
        try {
            $durationMinutes = [math]::Round(($now - $p.StartTime).TotalMinutes, 2)
            if ($durationMinutes -gt 1) {
                $newData += [PSCustomObject]@{ Date = $now.ToString("yyyy-MM-dd"); Name = $p.ProcessName; Duration = $durationMinutes }
            }
        } catch {}
    }
    $history = @()
    if (Test-Path $LogFile) { try { $history = Get-Content $LogFile | ConvertFrom-Json } catch { $history = @() } }
    $history += $newData
    if ($history.Count -gt 5000) { $history = $history | Select-Object -Last 5000 }
    $history | ConvertTo-Json -Depth 2 | Set-Content $LogFile
    Write-Host "$(Color-Text 'Database Updated.' $Hex.LightGreen)"
    Start-Sleep -Seconds 1
}

function Get-ActivityStats {
    if (-not (Test-Path $LogFile)) { Write-Host "`n$(Color-Text 'No History Found. Run [6] first.' $Hex.Red)"; return }
    $history = Get-Content $LogFile | ConvertFrom-Json
    if ($history.Count -eq 0) { return }
    Write-Host "`n$(Color-Text '[INTELLIGENCE REPORT]' $Hex.BrightGreen)"
    function Draw-ChartBlock ($Title, $Data, $IsAvg=$false) {
        Write-Host "`n$(Color-Text $Title $Hex.LightGreen)"
        if ($IsAvg) {
            $sorted = $Data | Group-Object Name | Select-Object Name, @{N='Value';E={ [math]::Round(($_.Group | Measure-Object Duration -Average).Average, 0) }} | Sort-Object Value -Descending | Select-Object -First 5
            $unit = "m/s"
        } else {
            $sorted = $Data | Group-Object Name | Select-Object Name, @{N='Value';E={ [math]::Round(($_.Group | Measure-Object Duration -Sum).Sum / 60, 1) }} | Sort-Object Value -Descending | Select-Object -First 5
            $unit = "h"
        }
        if ($sorted.Count -gt 0) {
            $maxValue = ($sorted | Measure-Object -Property Value -Maximum).Maximum
            $chartLines = @()
            foreach ($row in $sorted) { $chartLines += Draw-Bar -Label $row.Name -Value $row.Value -Max $maxValue -Unit $unit }
            Center-Block -Lines $chartLines
        }
    }
    Draw-ChartBlock "::: MOST USED (ALL TIME) :::" $history
    Draw-ChartBlock "::: AVG SESSION DURATION :::" $history -IsAvg $true
}

function Start-LiveDashboard {
    $running = $true
    try { [Console]::CursorVisible = $false } catch {}
    
    while ($running) {
        if ([Console]::KeyAvailable) { $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown"); break }
        
        Clear-Host
        # Compact Static Header
        Write-Host "==========================================================" -ForegroundColor DarkGreen
        Write-Host "  SENTRY LIVE HUD  |  PRESS ANY KEY TO EXIT" -ForegroundColor Green
        Write-Host "==========================================================" -ForegroundColor DarkGreen
        Write-Host ""

        $procs = Get-Process
        $totalMem = [math]::Round(($procs | Measure-Object WorkingSet -Sum).Sum / 1GB, 2)
        $topCPU = $procs | Sort-Object CPU -Descending | Select-Object -First 10
        
        # Left-Aligned Data Display
        Write-Host " [ SYSTEM VITALS ]" -ForegroundColor Cyan
        Write-Host " Total Memory Usage: $totalMem GB" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " [ TOP PROCESSES BY CPU ]" -ForegroundColor Cyan
        
        foreach ($p in $topCPU) {
            if ($p.CPU) {
                $val = [math]::Round($p.CPU, 0)
                # Using fixed width bars to prevent wrapping glitches
                $bar = Draw-Bar -Label $p.ProcessName -Value $val -Max 1000 -Width 30 -Unit "s"
                Write-Host $bar
            }
        }
        
        Start-Sleep -Milliseconds 1200
    }
    try { [Console]::CursorVisible = $true } catch {}
}

function Export-Report {
    Write-Host "`n$(Color-Text '[EXPORTING REPORT]' $Hex.BrightGreen)"
    Write-Host "$(Color-Text 'Gathering system intelligence...' $Hex.SageGreen)"
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    
    $path1 = "$PSScriptRoot\Sentry_Report_$timestamp.txt"
    $path2 = "$HOME\Downloads\Sentry_Report_$timestamp.txt"
    
    $report = @()
    
    $report += "==========================================================="
    $report += " SENTRY - SYSTEM INTELLIGENCE REPORT"
    $report += " Generated: $(Get-Date)"
    $report += " Hostname:  $env:COMPUTERNAME"
    $report += " User:      $env:USERNAME"
    $report += "==========================================================="
    $report += ""
    
    $report += "[ TOP 10 CPU CONSUMERS ]"
    $report += Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Id, ProcessName, CPU -AutoSize | Out-String
    
    $report += "[ TOP 10 MEMORY CONSUMERS ]"
    $report += Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 | Format-Table Id, ProcessName, @{N='Memory(MB)';E={[math]::Round($_.WorkingSet/1MB,2)}} -AutoSize | Out-String
    
    $report += "[ ACTIVE EXTERNAL CONNECTIONS (TCP ESTABLISHED / UDP LISTEN) ]"
    $tcp = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0" } | Select-Object @{N='Type';E={'TCP'}}, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    $udp = Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -ne "127.0.0.1" -and $_.LocalAddress -ne "::1" } | Select-Object @{N='Type';E={'UDP'}}, LocalAddress, LocalPort, @{N='RemoteAddress';E={'*'}}, @{N='RemotePort';E={'*'}}, @{N='State';E={'Open'}}, OwningProcess
    
    $report += ($tcp + $udp) | Format-Table -AutoSize | Out-String
    
    $report += "[ POTENTIALLY SUSPICIOUS PROCESSES ]"
    $suspicious = @()
    foreach ($p in Get-Process) {
        if ($p.Id -eq 0 -or [string]::IsNullOrEmpty($p.Path)) { continue }
        $reason = ""
        if ($p.Path -match "AppData" -or $p.Path -match "Temp") { $reason += "[Suspicious Path] " }
        if ($p.Path -notmatch "Windows\\System32") {
             try { $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue; if ($sig.Status -ne "Valid") { $reason += "[Unsigned] " } } catch {}
        }
        if ($reason) { $suspicious += [PSCustomObject]@{ PID=$p.Id; Name=$p.ProcessName; Reason=$reason; Path=$p.Path } }
    }
    if ($suspicious) { $report += $suspicious | Format-Table -AutoSize | Out-String } else { $report += "No threats detected." }

    $report | Set-Content $path1
    $report | Set-Content $path2
    
    Write-Host "$(Color-Text 'Report Saved Successfully:' $Hex.LightGreen)"
    Write-Host "1. $path1" -ForegroundColor Gray
    Write-Host "2. $path2" -ForegroundColor Gray
}

# --- MAIN EXECUTION LOOP ---

do {
    Clear-Host
    Show-Header
    
    $menuData = @(
        [PSCustomObject]@{ Key="1"; Desc="View Top Memory Hogs" }, 
        [PSCustomObject]@{ Key="2"; Desc="View Top CPU Hogs" },
        [PSCustomObject]@{ Key="3"; Desc="Startup Apps Manager" },
        [PSCustomObject]@{ Key="4"; Desc="View Network Active Processes" }, 
        [PSCustomObject]@{ Key="5"; Desc="Scan for 'Shady' Processes" },
        [PSCustomObject]@{ Key="6"; Desc="Manage Process (Kill/Freeze/Prio)" }, 
        [PSCustomObject]@{ Key="7"; Desc="Log Current Activity" },
        [PSCustomObject]@{ Key="8"; Desc="View Usage Intelligence" }, 
        [PSCustomObject]@{ Key="9"; Desc="Live Dashboard (HUD)" }, 
        [PSCustomObject]@{ Key="0"; Desc="Export System Report (.txt)" },
        [PSCustomObject]@{ Key="Q"; Desc="Quit" }
    )
    
    $maxOptWidth = ($menuData | ForEach-Object { $_.Desc.Length } | Measure-Object -Maximum).Maximum + 10
    $windowWidth = Get-WindowWidth
    $blockPadding = [math]::Max(0, [math]::Floor(($windowWidth - $maxOptWidth) / 2))
    $paddingStr = " " * $blockPadding
    $bL = Color-Text "[" $Hex.OliveGreen
    $bR = Color-Text "]" $Hex.OliveGreen

    foreach ($item in $menuData) {
        $keyColored  = Color-Text (" " + $item.Key + " ") $Hex.LightGreen
        $descColored = Color-Text $item.Desc $Hex.SageGreen
        Write-Host "$paddingStr$bL$keyColored$bR $descColored"
    }
    Write-Host "`n"
    $choice = Get-SafeInput -Prompt "Select option" -MaxLength 1
    
    if ($choice -ne 'Q' -and $choice -ne $null) { Clear-Host; Show-Header }

    switch ($choice) {
        '1' { Get-ResourceHogs -Type "Memory" } 
        '2' { Get-ResourceHogs -Type "CPU" }    
        '3' { Manage-StartupApps } 
        '4' { Get-NetworkProcs; Pause }
        '5' { Analyze-ShadyProcs; Pause }
        '6' { Manage-Process }
        '7' { Update-ActivityLog; Pause }
        '8' { Get-ActivityStats; Pause }
        '9' { Start-LiveDashboard }
        '0' { Export-Report; Pause }
        'Q' { Clear-Host; Write-Host "Exiting..."; break }
        $null { }
        Default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} while ($choice -ne 'Q')