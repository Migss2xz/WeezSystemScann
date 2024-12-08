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
Write-Host "Elapsed Time $t Minutes" -ForegroundColor White

# Interaction menu
Write-Host ""
Write-Host "Select an option:"
Write-Host -ForegroundColor Green "A. " -NoNewLine; Write-Host -ForegroundColor White "Display system information in a new window"
Write-Host -ForegroundColor Green "B. " -NoNewLine; Write-Host -ForegroundColor White "Display current/recent devices plugged into the computer"
Write-Host ""


$selection = Read-Host "Enter your choice (A/B)"

switch ($selection) {
    "A" {
        # Create a new cmd window with smaller size and redirect output to a file, then display it with scrolling
        $outputFile = [System.IO.Path]::GetTempFileName()

        # Adjusting the cmd window size and allowing scrolling through systeminfo
        Start-Process cmd -ArgumentList "/K", "mode con: cols=80 lines=20 & systeminfo > $outputFile & type $outputFile | more"
    }
    "B" {
        $output = @"
Currently Connected USB Devices:
"@
        $usbDevices = Get-WmiObject -Query "SELECT * FROM Win32_USBHub"
        $usbDevicesFormatted = $usbDevices | Select-Object DeviceID, PNPDeviceID, Description, DeviceName
        $usbDevicesFormatted | ForEach-Object { $output += "$($_.Description) - Device ID: $($_.DeviceID)`n" }

        $output += "`nCurrently Connected Keyboards:`n"
        $keyboards = Get-WmiObject -Class Win32_Keyboard
        $keyboardsFormatted = $keyboards | Select-Object DeviceID, PNPDeviceID, Description
        $keyboardsFormatted | ForEach-Object { $output += "$($_.Description) - Device ID: $($_.DeviceID)`n" }

        $output += "`nCurrently Connected Mice:`n"
        $mice = Get-WmiObject -Class Win32_PointingDevice
        $miceFormatted = $mice | Select-Object DeviceID, PNPDeviceID, Description
        $miceFormatted | ForEach-Object { $output += "$($_.Description) - Device ID: $($_.DeviceID)`n" }

        $output += "`nCurrently Connected Audio Devices (Headsets/Speakers):`n"
        $audioDevices = Get-WmiObject -Class Win32_SoundDevice
        $audioDevicesFormatted = $audioDevices | Select-Object DeviceID, PNPDeviceID, Description
        $audioDevicesFormatted | ForEach-Object { $output += "$($_.Description) - Device ID: $($_.DeviceID)`n" }

        # Get Recently Removed USB Devices (Device Removal Events)
        $removedUsbEvents = Get-WinEvent -LogName System | Where-Object { $_.Id -eq 2102 -or $_.Id -eq 2103 } | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending
        $output += "`nRecently Removed USB Devices:`n"
        if ($removedUsbEvents.Count -gt 0) {
            $removedUsbEvents | ForEach-Object { $output += "Event ID: $($_.Id) - $($_.Message) at $($_.TimeCreated)`n" }
        } else {
            $output += "No recently removed USB devices found.`n"
        }

        # Get Recently Removed Devices (General Device Removal Events)
        $removedDevicesEvents = Get-WinEvent -LogName System | Where-Object { $_.Id -eq 104 -or $_.Id -eq 2003 } | Select-Object TimeCreated, Id, Message | Sort-Object TimeCreated -Descending
        $output += "`nGeneral Device Removal Events:`n"
        if ($removedDevicesEvents.Count -gt 0) {
            $removedDevicesEvents | ForEach-Object { $output += "Event ID: $($_.Id) - $($_.Message) at $($_.TimeCreated)`n" }
        } else {
            $output += "No recent general device removal events found.`n"
        }

        # Check for PCI Devices (Potential DMA Boards)
        $pciDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.DeviceID -match "PCI" }
        $dmaDevices = $pciDevices | Where-Object { $_.Description -match "DMA" }
        $output += "`nChecking for DMA-related Devices:`n"
        if ($dmaDevices.Count -gt 0) {
            $dmaDevices | ForEach-Object { $output += "DMA-Related Device Found: $($_.Description) - Device ID: $($_.DeviceID)`n" }
        } else {
            $output += "No DMA-related devices found.`n"
        }

        # Create a new CMD process to display the output in a new command prompt window
        $outputFilePath = [System.IO.Path]::GetTempFileName()
        Set-Content -Path $outputFilePath -Value $output
        Start-Process cmd.exe -ArgumentList "/c type $outputFilePath"
    }
}
