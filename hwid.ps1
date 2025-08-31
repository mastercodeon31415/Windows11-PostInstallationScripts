<#
.SYNOPSIS
    A comprehensive PowerShell script to perform initial setup and configuration for a new Windows installation.
.DESCRIPTION
    This script automates a variety of post-installation tasks to optimize and configure a Windows environment.
    It is organized into distinct functions for clarity and maintainability.

    The script performs the following actions:
    - Checks for and runs with Administrator privileges.
    - Enables essential virtualization features (Hyper-V, WSL, Virtual Machine Platform).
    - Applies a wide range of performance and usability registry tweaks:
        - Speeds up system shutdown time and menu display.
        - Optimizes system and network responsiveness.
        - Disables Power Throttling and CPU Core Parking.
        - Applies gaming-specific performance optimizations.
        - Enables Developer Mode and Explorer item checkboxes.
    - Downloads and executes a script to attempt Windows activation.
    - Installs optional features like Wireless Display.
    - Optimizes power settings by enabling the Ultimate Performance plan and disabling hibernation.
    - Manages system resources by disabling the SysMain service and setting a static page file size.
    - Adjusts network sharing settings for better local network compatibility.
    - Prompts for and performs a system restart to apply all changes.
.NOTES
    Author: Gemini
    Version: 3.0
    - This script makes significant changes to the system, including the Windows Registry and security settings.
    - Review the code carefully before execution to understand the changes being made.
    - It is intended to be run on a fresh Windows installation.
#>

# =============================================================================
# SCRIPT-LEVEL HELPER FUNCTIONS
# =============================================================================

function Get-FeatureState {
    <#
    .SYNOPSIS
        Checks the current state of a Windows feature using DISM.
    .PARAMETER FeatureName
        The name of the feature to check.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    try {
        $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:$FeatureName
        $stateLine = $dismOutput | Select-String -Pattern "State :"
        
        if ($stateLine -match "State : Enabled") { return "Enabled" }
        if ($stateLine -match "State : Disabled") { return "Disabled" }
        if ($stateLine -match "State : Enable Pending") { return "Enable Pending" }
        if ($stateLine -match "State : Disable Pending") { return "Disable Pending" }
        
        return "Unknown"
    }
    catch {
        Write-Error "An error occurred while getting the state of feature '$($FeatureName)': $_"
        return "Unknown"
    }
}

function Enable-Feature {
    <#
    .SYNOPSIS
        Enables a specific Windows feature using DISM.
    .PARAMETER FeatureName
        The name of the feature to enable.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )
    try {
        Write-Host "Attempting to enable feature: $FeatureName" -ForegroundColor Cyan
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:$FeatureName /All /NoRestart" -Wait -PassThru -WindowStyle Hidden
        
        # DISM exit code 3010 means a restart is required, which is a success condition here.
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Host "Successfully enabled feature: $FeatureName" -ForegroundColor Green
            return $true
        }
        else {
            Write-Error "Failed to enable feature: $FeatureName. Exit Code: $($process.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Error "An exception occurred while enabling '$($FeatureName)': $_"
        return $false
    }
}


# =============================================================================
# CONFIGURATION FUNCTIONS
# =============================================================================

function Enable-VirtualizationFeatures {
    <#
    .SYNOPSIS
        Enables Windows features necessary for virtualization and Linux subsystems.
    .DESCRIPTION
        This function checks for and enables Hyper-V, the Virtual Machine Platform,
        the Hypervisor Platform, and the Windows Subsystem for Linux (WSL).
    .NOTES
        Returns $true if a restart is required, otherwise $false.
    #>
    Write-Host "`n=== Enabling Virtualization Features ===" -ForegroundColor Yellow
    $features = @(
        "Microsoft-Hyper-V-All",
        "VirtualMachinePlatform",
        "HypervisorPlatform",
		"Microsoft-Windows-Subsystem-Linux"
    )

    $restartRequired = $false
    foreach ($feature in $features) {
        $state = Get-FeatureState -FeatureName $feature
        Write-Host "Feature '$($feature)' state is: $state"

        if ($state -eq "Disabled") {
            if (Enable-Feature -FeatureName $feature) {
                $restartRequired = $true
            }
        }
        elseif ($state -in ("Enable Pending", "Disable Pending")) {
            Write-Warning "Status of feature '$($feature)' is pending. A restart is required."
            $restartRequired = $true
        }
    }
    return $restartRequired
}

function Apply-PerformanceAndRegistryTweaks {
    <#
    .SYNOPSIS
        Applies a wide range of registry modifications for system performance, gaming, and user experience.
    .DESCRIPTION
        This function modifies the Windows Registry to apply the following tweaks:
        - Speeds up system shutdown by lowering the 'WaitToKillServiceTimeout'.
        - Optimizes system responsiveness for multimedia applications.
        - Reduces the delay for menus to appear.
        - Maximizes network throughput by disabling throttling.
        - Disables power throttling to prevent the CPU from being limited under load.
        - Disables CPU core parking to ensure all cores are available.
        - Prioritizes GPU and CPU resources for games.
        - Enables checkboxes for item selection in File Explorer.
        - Enables Developer Mode for app sideloading.
        - Removes the artificial startup delay for applications after booting.
    #>
    Write-Host "`n=== Applying Performance and Registry Tweaks ===" -ForegroundColor Yellow
    try {
        # Tweak: Speed up shutdown time
        Write-Host "Applying tweak: Speeding up shutdown time..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value 500 -Type String -Force

        # Tweak: Optimize system responsiveness
        Write-Host "Applying tweak: Optimizing system responsiveness..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 10 -Type DWord -Force

        # Tweak: Speed up menu show delay
        Write-Host "Applying tweak: Speeding up menu show delay..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 100 -Type String -Force

        # Tweak: Increase network performance (disable throttling)
        Write-Host "Applying tweak: Increasing network performance..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord -Force

        # Tweak: Disable power throttling
        Write-Host "Applying tweak: Disabling power throttling..." -ForegroundColor Cyan
        $powerThrottlingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
        if (-not (Test-Path -Path $powerThrottlingPath)) { New-Item -Path $powerThrottlingPath -Force | Out-Null }
        Set-ItemProperty -Path $powerThrottlingPath -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force

        # Tweak: Disable CPU core parking
        Write-Host "Applying tweak: Disabling CPU core parking..." -ForegroundColor Cyan
        $coreParkingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"
        Set-ItemProperty -Path $coreParkingPath -Name "Attributes" -Value 0 -Type DWord -Force

        # Tweak: Optimize gaming performance
        Write-Host "Applying tweak: Optimizing gaming performance..." -ForegroundColor Cyan
        $gamingProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
        if (-not (Test-Path -Path $gamingProfilePath)) { New-Item -Path $gamingProfilePath -Force | Out-Null }
        Set-ItemProperty -Path $gamingProfilePath -Name "GPU Priority" -Value 8 -Type DWord -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "Affinity" -Value 0xf -Type DWord -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "Background Only" -Value "False" -Type String -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "Background Priority" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "Priority" -Value 6 -Type DWord -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "Scheduling Category" -Value "High" -Type String -Force
        Set-ItemProperty -Path $gamingProfilePath -Name "SFIO Priority" -Value "High" -Type String -Force

        # Tweak: Enable checkboxes in File Explorer
        Write-Host "Applying tweak: Enabling File Explorer checkboxes..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Value 1 -Type DWord -Force

        # Tweak: Enable Developer Mode
        Write-Host "Applying tweak: Enabling Developer Mode..." -ForegroundColor Cyan
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord -Force

        # Tweak: Remove startup delay for programs
        Write-Host "Applying tweak: Removing application startup delay..." -ForegroundColor Cyan
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Type DWord -Force

        Write-Host "All registry tweaks applied successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while applying registry tweaks: $_"
    }
}

function Attempt-WindowsActivation {
    <#
    .SYNOPSIS
        Downloads and runs an external script to attempt HWID (Digital License) activation.
    .DESCRIPTION
        This function downloads an activation script from the 'massgravel' GitHub repository,
        modifies it to run automatically, executes it, and then cleans up the temporary file.
    .NOTES
        This uses a third-party script for activation. Use at your own discretion.
    #>
    Write-Host "`n=== Attempting Windows Activation ===" -ForegroundColor Yellow
    $url = "https://github.com/massgravel/Microsoft-Activation-Scripts/raw/refs/heads/master/MAS/Separate-Files-Version/Activators/HWID_Activation.cmd"
    $decodedFile = Join-Path -Path $env:TEMP -ChildPath "hwid.bat"

    try {
        Write-Host "Setting security protocol to TLS 1.2..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = 'tls12'

        Write-Host "Downloading activation script from: $url" -ForegroundColor Cyan
        $webClient = New-Object Net.WebClient
        # Modify the script on-the-fly to automate its activation choice
	    $scriptContent = $webClient.DownloadString($url).Replace('set _act=0', 'set _act=1')
        
        [System.IO.File]::WriteAllText($decodedFile, $scriptContent)
        Write-Host "Activation script saved to: $decodedFile" -ForegroundColor Green

        Write-Host "Executing activation script..." -ForegroundColor Cyan
        cmd /c call $decodedFile
        
        Write-Host "Cleaning up temporary activation file..." -ForegroundColor Cyan
        Remove-Item -Path $decodedFile -Force
        Write-Host "Activation process complete." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred during the activation process: $_"
    }
}

function Install-OptionalFeatures {
    <#
    .SYNOPSIS
        Installs optional Windows capabilities.
    .DESCRIPTION
        This function uses DISM to add the "Wireless Display" capability, which allows
        the computer to function as a Miracast receiver.
    #>
    Write-Host "`n=== Installing Optional Features ===" -ForegroundColor Yellow
    try {
        Write-Host "Installing Wireless Display feature..." -ForegroundColor Cyan
        DISM /Online /Add-Capability /CapabilityName:App.WirelessDisplay.Connect~~~~0.0.1.0
        Write-Host "Wireless Display feature installed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Wireless Display feature: $_"
    }
}

function Configure-PowerSettings {
    <#
    .SYNOPSIS
        Optimizes system power settings for maximum performance.
    .DESCRIPTION
        - Enables and activates the 'Ultimate Performance' power plan.
        - Disables hibernation to free up disk space by removing hiberfil.sys.
    #>
    Write-Host "`n=== Configuring Power Settings ===" -ForegroundColor Yellow
    
    # Enable and set Ultimate Performance Power Plan
    Write-Host "Enabling Ultimate Performance power plan..." -ForegroundColor Cyan
    $guid = (powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Select-String -Pattern '([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12})').Matches.Value
    if ($guid) {
        powercfg /setactive $guid
        Write-Host "Successfully set Ultimate Performance power plan as active." -ForegroundColor Green
    } else {
        Write-Error "Could not find the GUID for the Ultimate Performance power plan."
    }

    # Disable hibernation
    Write-Host "Disabling hibernation..." -ForegroundColor Cyan
    powercfg -h off
    Write-Host "Hibernation disabled." -ForegroundColor Green
}

function Optimize-SystemPerformance {
    <#
    .SYNOPSIS
        Applies configurations to optimize system resources.
    .DESCRIPTION
        - Disables the SysMain (formerly Superfetch) service to reduce background I/O.
        - Sets a fixed page file size to prevent dynamic resizing and save disk space.
    .NOTES
        Returns $true if a restart is required for the page file change, otherwise $false.
    #>
    Write-Host "`n=== Optimizing System Performance ===" -ForegroundColor Yellow
    $restartRequired = $false

    # Disable SysMain (Superfetch)
    Write-Host "Disabling SysMain (Superfetch) service..." -ForegroundColor Cyan
    try {
        Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name "SysMain" -Force -ErrorAction Stop
        Write-Host "SysMain service has been stopped and disabled." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to disable SysMain service. It may already be disabled or not exist."
    }

    # Set a static page file size (e.g., 4GB)
    Write-Host "Configuring page file..." -ForegroundColor Cyan
    try {
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($ComputerSystem.AutomaticManagedPagefile) {
            $ComputerSystem.AutomaticManagedPagefile = $false
            Set-CimInstance -InputObject $ComputerSystem
            Write-Host "Disabled automatic page file management."
        }
        
        $InitialSizeMB = 4096
        $MaximumSizeMB = 4096
        
        $PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'"
        if ($PageFile) {
            $PageFile.InitialSize = $InitialSizeMB
            $PageFile.MaximumSize = $MaximumSizeMB
            Set-CimInstance -InputObject $PageFile
        } else {
            New-CimInstance -ClassName Win32_PageFileSetting -Property @{Name = 'C:\pagefile.sys'; InitialSize = $InitialSizeMB; MaximumSize = $MaximumSizeMB}
        }
        
        Write-Host "Successfully set page file to a static size of $InitialSizeMB MB." -ForegroundColor Green
        $restartRequired = $true
    }
    catch {
        Write-Error "Failed to configure the page file. Error: $($_.Exception.Message)"
    }
    return $restartRequired
}

function Configure-NetworkSharing {
    <#
    .SYNOPSIS
        Adjusts security settings to improve compatibility for local network file sharing (SMB).
    .DESCRIPTION
        - Allows local accounts with blank passwords to log on over the network.
        - Enables insecure guest logons for the SMB client.
        - Disables the requirement for security signatures on SMB connections.
    .NOTES
        These changes reduce security. Only use this on trusted private networks.
    #>
    Write-Host "`n=== Configuring Network Sharing (SMB) Settings ===" -ForegroundColor Yellow
    try {
        # Allow blank passwords for network logon
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0 -Force
        Write-Host "Allowed local accounts with blank passwords for network logon." -ForegroundColor Green
        
        # Configure SMB for better compatibility
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
        Write-Host "Enabled insecure guest logons and disabled SMB security signature requirements." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while configuring network sharing: $_"
    }
}

function Invoke-SystemReboot {
    <#
    .SYNOPSIS
        Prompts the user and forcefully restarts the computer to apply all changes.
    .PARAMETER Needed
        A switch parameter that, if present, indicates a restart is mandatory for certain changes to take effect.
    #>
    param (
        [switch]$Needed
    )

    Write-Host "`n=== System Restart Required ===" -ForegroundColor Yellow
    if ($Needed) {
        Write-Host "One or more changes require a system restart to take effect." -ForegroundColor Green
    } else {
         Write-Host "A system restart is recommended to ensure all changes are applied correctly." -ForegroundColor Green
    }
    
    Write-Host "The computer will restart in 10 seconds. Press Ctrl+C to abort." -ForegroundColor Red
    Start-Sleep -Seconds 10
    shutdown /r /t 0
}


# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Step 1: Ensure the script is running with administrative privileges
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Attempting to re-launch as Admin..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($PSCommandPath)`""
    Exit
}

# Step 2: Announce the start of the script
Write-Host "================================================="
Write-Host "  WINDOWS POST-INSTALLATION CONFIGURATION SCRIPT "
Write-Host "================================================="

# Step 3: Execute configuration functions and track if a restart is needed
$restartIsNeeded = $false

if (Enable-VirtualizationFeatures) { $restartIsNeeded = $true }
Apply-PerformanceAndRegistryTweaks
Attempt-WindowsActivation
Install-OptionalFeatures
Configure-PowerSettings
if (Optimize-SystemPerformance) { $restartIsNeeded = $true }
Configure-NetworkSharing

# VMWare Tools silent installation
$filePath = "C:\VMware-tools-windows-13.0.1-24843032\setup.exe"
$arguments = "" # "/s /v/qn"
# Check if the file exists
if (Test-Path $filePath) {
    # If the file exists, run it with arguments
    Start-Process $filePath -ArgumentList $arguments
} else {
    Write-Host "File does not exist."
}

# Step 4: Reboot the system to apply all changes

#Invoke-SystemReboot -Needed:$true