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

 Interaction menu
Write-Host ""
Write-Host "Select an option:"
Write-Host -ForegroundColor Green "A. " -NoNewLine; Write-Host -ForegroundColor White "Display system information in a new window"
Write-Host -ForegroundColor Green "B. " -NoNewLine; Write-Host -ForegroundColor White "Display recent Anti-Virus logs/flags"
Write-Host -ForegroundColor Green "C. " -NoNewLine; Write-Host -ForegroundColor White "List Installed Software"
Write-Host -ForegroundColor Green "D. " -NoNewLine; Write-Host -ForegroundColor White "Display Recent User Logins"
Write-Host -ForegroundColor Green "E. " -NoNewLine; Write-Host -ForegroundColor White "View Security and Anti-Malware Scan History"
Write-Host -ForegroundColor Green "F. " -NoNewLine; Write-Host -ForegroundColor White "Check for Local User Accounts"
Write-Host -ForegroundColor Red "X. " -NoNewLine; Write-Host -ForegroundColor White "Exit"

$selection = Read-Host "Enter your choice (A/B/C/D/E/F/X)"

switch ($selection) {
    "A" {
        # Create a new cmd window with smaller size and redirect output to a file, then display it with scrolling
        $outputFile = [System.IO.Path]::GetTempFileName()
        Start-Process cmd.exe -ArgumentList "/K", "mode con: cols=80 lines=20 && systeminfo > $outputFile && type $outputFile | more"
    }
    "B" {
        # Option B: Display all Protection history (Real-Time Protection events, Threat Detection, and Antivirus Actions)
        $logName = 'Microsoft-Windows-Security/Operational'
        $eventIDs = @(5001, 5002, 1116, 1117, 1118, 1119, 5007, 5010)
        try {
            $protectionLogs = Get-WinEvent -LogName $logName | Where-Object { $eventIDs -contains $_.Id } | Sort-Object TimeCreated | Select-Object -First 20
            if ($protectionLogs.Count -eq 0) {
                Write-Host "No relevant logs found." -ForegroundColor Red
            } else {
                $logOutput = ""
                foreach ($log in $protectionLogs) {
                    $eventTime = $log.TimeCreated
                    $eventMessage = $log.Message
                    $eventID = $log.Id
                    $logOutput += "$eventTime - Event ID $eventID: $eventMessage`n"
                }
                Write-Host $logOutput
            }
        } catch {
            Write-Host "Error fetching logs: $_" -ForegroundColor Red
        }
    }
    "C" {
        # List Installed Software
        Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name
    }
    "D" {
        # Recent User Logins
        $logonEvents = Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 528 } | Select-Object -First 10
        $logonEvents | ForEach-Object {
            $username = ($_ | Select-Object -ExpandProperty Message) -match "Account Name:\s+(\w+)" | Out-Null; $matches[1]
            $logonTime = $_.TimeCreated
            Write-Host "User: $username - Logged in at: $logonTime"
        }
    }
    "E" {
        # Display Security and Anti-Malware Scan History
        Get-WinEvent -LogName 'Microsoft-Windows-Security/Operational' -FilterXPath "*[EventData[Data[@Name='ActionType'] and (Data='Scan')]]" | Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | Format-Table -AutoSize
    }
    "F" {
        # Check for local user accounts
        try {
            $userAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
            $accountCount = $userAccounts.Count
            if ($accountCount -eq 0) {
                Write-Host "No local user accounts found." -ForegroundColor Red
            } elseif ($accountCount -eq 1) {
                Write-Host "There is 1 local user account." -ForegroundColor Green
            } else {
                Write-Host "There are $accountCount local user accounts." -ForegroundColor Green
            }
            $userAccounts | Select-Object Name, Disabled, Lockout | Format-Table -AutoSize
        } catch {
            Write-Host "Error fetching user accounts: $_" -ForegroundColor Red
        }
    }
    "X" {
        # Exit the script
        Write-Host "Exiting... Goodbye!" -ForegroundColor Yellow
        break
    }
    default {
        Write-Host "Invalid selection, please choose A, B, C, D, E, F, or X." -ForegroundColor Red
    }
}
