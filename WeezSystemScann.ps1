$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (NotSigned)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (HashMismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (NotTrusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (UnknownError)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}

Clear-Host

Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Green "   ██╗    ██╗███████╗███████╗███████╗    ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗███████╗"
Write-Host -ForegroundColor Green "   ██║    ██║██╔════╝██╔════╝╚══███╔╝    ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║██╔════╝"
Write-Host -ForegroundColor Green "   ██║ █╗ ██║█████╗  █████╗    ███╔╝     ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║███████╗"
Write-Host -ForegroundColor Green "   ██║███╗██║██╔══╝  ██╔══╝   ███╔╝      ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║╚════██║"
Write-Host -ForegroundColor Green "   ╚███╔███╔╝███████╗███████╗███████╗    ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║███████║"
Write-Host -ForegroundColor Green "    ╚══╝╚══╝ ╚══════╝╚══════╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝╚══════╝"
Write-Host ""
Write-Host -ForegroundColor White "   Made By Migss2x On Discord | Weez System Scanning - " -NoNewLine
Write-Host -ForegroundColor green "discord.gg/weezsystems"
Write-Host ""

function Test-Admin {;$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent());$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);}
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try{New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE}
    Catch{Write-Warning "Error Mounting HKEY_Local_Machine"}
}
$bv = ("bam", "bam\State")
Try{$Users = foreach($ii in $bv){Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName}}
Catch{
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}
$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

$Bam = Foreach ($Sid in $Users){$u++
            
        foreach($rp in $rpath){
           $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
           Write-Host -ForegroundColor Green "Extracting " -NoNewLine
           Write-Host -ForegroundColor White "$($rp)UserSettings\$SID"
           $bi = 0 

            Try{
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate( [System.Security.Principal.NTAccount]) 
            $User = $User.Value
            }
            Catch{$User=""}
            $i=0
            ForEach ($Item in $BamItems){$i++
		    $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty $Item
	
            If($key.length -eq 24){
                $Hex=[System.BitConverter]::ToString($key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
			    $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
			    $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
			    $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2)) 
			    $Biasd = $Bias/60
			    $Dayd = $Day/60
			    $TImeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).addminutes($Bias) -Format "yyyy-MM-dd HH:mm:ss") 
			    $d = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {((split-path -path $item).Remove(23)).trimstart("\Device\HarddiskVolume")} else {$d = ""} 
			    $f = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Split-path -leaf ($item).TrimStart()} else {$item}	
			    $cp = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {($item).Remove(1,23)} else {$cp = ""} 
			    $path = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Join-Path -Path "C:" -ChildPath $cp} else {$path = ""}			
			    $sig = if((((split-path -path $item) | ConvertFrom-String -Delimiter "\\").P3)-match '\d{1}')
			    {Get-Signature -FilePath $path} else {$sig = ""}				
                [PSCustomObject]@{
                            'Examiner Time' = $TimeLocal
						    'Last Execution Time (UTC)'= $TimeUTC
						    'Last Execution User Time' = $TimeUser
                             Signature =          $Sig
						     User =         $User
						     SID =          $Sid
                             Regpath =        $rp
                             }}}}}


$Bam | Out-GridView -PassThru -Title "BAM key entries $($Bam.count)  - User TimeZone: ($UserTime) -> ActiveBias: ( $Bias) - DayLightTime: ($Day)"

$sw.stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host ""
Write-Host "Elapsed Time $t Minutes" -ForegroundColor Red

# Interaction menu
Write-Host ""
Write-Host "Select an option:"
Write-Host -ForegroundColor Green "A. " -NoNewLine; Write-Host -ForegroundColor White "Display system information in a new window"
Write-Host -ForegroundColor Green "B. " -NoNewLine; Write-Host -ForegroundColor White "Display recent Anti-Virus logs/flags"

$selection = Read-Host "Enter your choice (A/B)"

switch ($selection) {
    "A" {
        # Create a new cmd window with smaller size and redirect output to a file, then display it with scrolling
        $outputFile = [System.IO.Path]::GetTempFileName()

        # Adjusting the cmd window size and allowing scrolling through systeminfo
        Start-Process cmd.exe -ArgumentList "/K", "mode con: cols=80 lines=20 && systeminfo > $outputFile && type $outputFile | more"
    }
    "B" {
        # Option B: Display all Protection history (Real-Time Protection events, Threat Detection, and Antivirus Actions)
        
        # Define the log name for Security and Operational events
        $logName = 'Microsoft-Windows-Security/Operational'
        
        # Event IDs related to Real-Time Protection and Threat Detection
        $eventIDs = @(5001, 5002, 1116, 1117, 1118, 1119, 5007, 5010) # Includes events for Real-Time Protection ON/OFF, Threat Detection, Antivirus Actions
        
        # Get recent logs related to Real-Time Protection and Threat Detection
        try {
            $protectionLogs = Get-WinEvent -LogName $logName | Where-Object { $eventIDs -contains $_.Id } | Sort-Object TimeCreated | Select-Object -First 20
            
            # Debug: Output to ensure we are getting logs
            if ($protectionLogs.Count -eq 0) {
                Write-Host "No relevant logs found." -ForegroundColor Red
            } else {
                # Prepare log output to store the formatted messages
                $logOutput = ""

                # Format and display each log entry with colored output for ON/OFF status
                foreach ($log in $protectionLogs) {
                    $eventTime = $log.TimeCreated
                    $eventMessage = $log.Message
                    $eventID = $log.Id
                    
                    # Build log output with colored formatting for the console window
                    if ($eventID -eq 5001) {
                        # Real-Time Protection turned ON (Green)
                        $logOutput += "$eventTime - Real-Time Protection ON: $eventMessage`n"
                    } elseif ($eventID -eq 5002) {
                        # Real-Time Protection turned OFF (Red)
                        $logOutput += "$eventTime - Real-Time Protection OFF: $eventMessage`n"
                    } elseif ($eventID -eq 1116) {
                        # Threat Detected (Yellow for warning)
                        $logOutput += "$eventTime - Threat Detected: $eventMessage`n"
                    } elseif ($eventID -eq 1117) {
                        # Threat Removed (Green for successful removal)
                        $logOutput += "$eventTime - Threat Removed: $eventMessage`n"
                    } elseif ($eventID -eq 1118) {
                        # Threat Quarantined (Cyan for action taken)
                        $logOutput += "$eventTime - Threat Quarantined: $eventMessage`n"
                    } elseif ($eventID -eq 1119) {
                        # Threat Action Failed (Red for failure)
                        $logOutput += "$eventTime - Threat Action Failed: $eventMessage`n"
                    } elseif ($eventID -eq 5007) {
                        # Antivirus Protection Action (Green for action success)
                        $logOutput += "$eventTime - Antivirus Protection Action: $eventMessage`n"
                    } elseif ($eventID -eq 5010) {
                        # Antivirus Protection Disabled (Red)
                        $logOutput += "$eventTime - Antivirus Protection Disabled: $eventMessage`n"
                    }
                }

                # If there is output to display, create a new cmd window to show the logs
                if ($logOutput) {
                    $outputFile = [System.IO.Path]::GetTempFileName()
                    Set-Content -Path $outputFile -Value $logOutput
                    Start-Process cmd.exe -ArgumentList "/K", "mode con: cols=80 lines=20 && type $outputFile | more"
                }
            }
        } catch {
            Write-Host "Error retrieving logs: $_" -ForegroundColor Red
        }
    }
}
