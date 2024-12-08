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
Write-Host -ForegroundColor Green "   Made By Migss2x On Discord | Weez System Scanning - " -NoNewLine
Write-Host -ForegroundColor green "discord.gg/weezsystems"
Write-Host ""

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)){
    Try { New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE }
    Catch { Write-Warning "Error Mounting HKEY_Local_Machine" }
}

$bv = ("bam", "bam\State")
Try {
    $Users = foreach($ii in $bv) { Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName }
}
Catch {
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")
$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

# Add System Information Display
Function Get-SystemInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cpu = Get-CimInstance -ClassName Win32_Processor
    $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }

    Write-Host "OS: $($os.Caption) Version $($os.Version)"
    Write-Host "CPU: $($cpu.Name)"
    Write-Host "Memory: $(($memory.Capacity / 1GB).ToString('N2')) GB"
    Write-Host "Disk Space: $($disk.DeviceID) Free Space: $(($disk.FreeSpace / 1GB).ToString('N2')) GB"
}

# Add Interactive Menu
Write-Host "Select an option:"
Write-Host "1. Scan BAM keys"
Write-Host "2. Verify file signatures"
Write-Host "3. Show system info"

$choice = Read-Host "Enter choice"

switch ($choice) {
    1 {
        # BAM Scan
        $Bam = Foreach ($Sid in $Users) {
            $u++
            foreach($rp in $rpath) {
                $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
                $progress = 0
                $BamItemsCount = $BamItems.Count
                ForEach ($Item in $BamItems) {
                    $progress++
                    $percentComplete = ($progress / $BamItemsCount) * 100
                    Write-Progress -PercentComplete $percentComplete -Status "Processing BAM Items" -Activity "Extracting BAM data"
                    
                    $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
                    # Other BAM Item Processing Logic...
                }
            }
        }
        $Bam | Out-GridView -PassThru -Title "BAM key entries"
    }
    2 {
        # Signature Verification
        $filePath = Read-Host "Enter file path to verify signature"
        $sig = Get-Signature -FilePath $filePath
        Write-Host "File Signature: $sig"
    }
    3 {
        # Show System Info
        Get-SystemInfo
    }
    default {
        Write-Host "Invalid choice"
    }
}

$sw.stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host ""
Write-Host "Elapsed Time $t Minutes" -ForegroundColor White
