<#
.SYNOPSIS
    Checks for and enables necessary virtualization features if they are not already enabled.
.DESCRIPTION
    This script ensures that the required Windows features for virtualization, such as Hyper-V, Virtual Machine Platform, and HypervisorPlatform, are enabled.
    If the script is not run as an administrator, it will attempt to re-launch itself with elevated privileges.
    It checks the status of each required feature and enables any that are disabled.
    Finally, it informs the user if a system restart is required for the changes to take effect.
.NOTES
    Author: Gemini
    Version: 1.0
#>

function Get-FeatureState {
    <#
    .SYNOPSIS
        Checks the current state of a Windows feature using DISM.
    .PARAMETER FeatureName
        The name of the feature to check.
    .EXAMPLE
        Get-FeatureState -FeatureName "Microsoft-Hyper-V-All"
    .RETURNS
        The current state of the feature (Enabled, Disabled, Enable Pending, Disable Pending, or Unknown).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )

    try {
        $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:$FeatureName
        $stateLine = $dismOutput | Select-String -Pattern "State :"
        
        if ($stateLine -match "State : Enabled") {
            return "Enabled"
        }
        elseif ($stateLine -match "State : Disabled") {
            return "Disabled"
        }
        elseif ($stateLine -match "State : Enable Pending") {
            return "Enable Pending"
        }
        elseif ($stateLine -match "State : Disable Pending") {
            return "Disable Pending"
        }
        else {
            return "Unknown"
        }
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
    .EXAMPLE
        Enable-Feature -FeatureName "Microsoft-Hyper-V-All"
    .RETURNS
        $true if the feature was enabled successfully (or requires a restart), $false otherwise.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FeatureName
    )

    try {
        Write-Host "Attempting to enable feature: $FeatureName"
        $process = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Enable-Feature /FeatureName:$FeatureName /All /NoRestart" -Wait -PassThru -WindowStyle Hidden
        
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Host "Successfully enabled feature: $FeatureName"
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

function Ensure-VirtualizationFeaturesEnabled {
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
            Write-Warning "Status of feature '$($feature)' is pending. A restart might be required."
            $restartRequired = $true
        }
    }

    if ($restartRequired) {
        Write-Host "One or more features have been enabled. A system restart is required for the changes to take effect."
    }
    else {
        Write-Host "All required virtualization features are already enabled or their status is pending a restart."
    }
}

cmd /c reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v AutoCheckSelect /t REG_DWORD /d 1 /f
cmd /c reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
cmd /c reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
cmd /c reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "WaitForIdleState" /t REG_DWORD /d 0 /f

# =============================================================================
# Script: Download and Decode File
# Description: This script downloads a Base64 encoded file from a URL,
#              decodes it, and saves the content to a new file.
# =============================================================================

# --- Configuration ---
# Use variables to make the script easy to update.
$url = "https://github.com/massgravel/Microsoft-Activation-Scripts/raw/refs/heads/master/MAS/Separate-Files-Version/Activators/HWID_Activation.cmd"
$tempDir = $env:TEMP # The temporary directory path
$decodedFile = Join-Path -Path $tempDir -ChildPath "hwid.bat"

# --- Main Logic ---
try {
    # Step 1: Set modern security protocol for web requests
    # This is necessary for connecting to sites like GitHub.
    Write-Host "Setting security protocol to TLS 1.2..."
    [Net.ServicePointManager]::SecurityProtocol = 'tls12'

    # Step 2: Download the Base64 file
    Write-Host "Downloading file from URL: $url"
    $webClient = New-Object Net.WebClient
	$script = $webClient.DownloadString($url).Replace('set _act=0', 'set _act=1');
    Write-Host "File successfully downloaded to: $downloadedFile"

    # Step 4: Save the decoded content to the destination file
    [System.IO.File]::WriteAllText($decodedFile, $script)
    Write-Host "✅ Success! Decoded file saved to: $decodedFile"
}
catch {
    # If any command in the 'try' block fails, this will run.
    Write-Error "❌ An error occurred:"
    Write-Error $_ # The $_ variable contains the specific error message.
    exit 1 # Exit the script with an error code.
}

DISM /Online /Add-Capability /CapabilityName:App.WirelessDisplay.Connect~~~~0.0.1.0

# Main execution
Ensure-VirtualizationFeaturesEnabled

# Call HWID Activation
cmd /c call %temp%\hwid.bat
cmd /c del %temp%\hwid.bat

# This script enables the Ultimate Performance power plan and sets it as active.

# Step 1: Execute the command to duplicate the power scheme and capture the output.
$output = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

# Step 2: Display the output to the console (optional).
Write-Output $output

# Step 3: Use a regular expression to extract the GUID from the output string.
$guid = ($output | Select-String -Pattern '([a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12})').Matches.Value

# Step 4: Check if a GUID was successfully extracted.
if ($guid) {
    # Step 5: If a GUID was found, set the new power scheme as active.
    powercfg /setactive $guid
    Write-Output "Successfully set Ultimate Performance power plan with GUID $guid as active."
} else {
    # Step 6: If no GUID was found, display an error message.
    Write-Error "Could not find the GUID for the Ultimate Performance power plan."
}

# Disable superfetch to save on system resources
cmd /c sc stop "SysMain" "&&" sc config "SysMain" start=disabled

# Disable hibernation so that the hiberfil.sys file is deleted (saves space)
powercfg -h off

# Set the page file to 4gb. For a system with 32gb of ram, by default windows alocates about 36gb for the page file, so we will save about 32 gb of space by doing this)
# Step 1: Disable automatic page file management. This is required to set a manual size.
Write-Host "Disabling Automatic Pagefile Management..."
try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($ComputerSystem.AutomaticManagedPagefile) {
        $ComputerSystem.AutomaticManagedPagefile = $false
        Set-CimInstance -InputObject $ComputerSystem
        Write-Host "Successfully disabled automatic management."
    } else {
        Write-Host "Automatic management was already disabled."
    }
}
catch {
    Write-Error "Failed to get computer system settings. Please ensure you are running PowerShell as an Administrator."
    return
}

# Step 2: Get the page file on the C: drive and set its size.
# The sizes are in Megabytes (MB). 4096MB = 4GB, 8192MB = 8GB.
$InitialSizeMB = 4096
$MaximumSizeMB = 4978

Write-Host "Attempting to set pagefile size for C: to Initial: $InitialSizeMB MB, Maximum: $MaximumSizeMB MB..."
try {
    $PageFile = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'" -ErrorAction Stop

    $PageFile.InitialSize = $InitialSizeMB
    $PageFile.MaximumSize = $MaximumSizeMB
    Set-CimInstance -InputObject $PageFile

    Write-Host "Successfully set the pagefile size."
    Write-Host "A REBOOT IS REQUIRED for these changes to take effect." -ForegroundColor Yellow
}
catch {
    # This block will run if Get-CimInstance fails to find a pagefile on C:
    Write-Warning "Could not find an existing pagefile on C:. Attempting to create a new one."
    try {
        New-CimInstance -ClassName Win32_PageFileSetting -Property @{Name = 'C:\pagefile.sys'; InitialSize = $InitialSizeMB; MaximumSize = $MaximumSizeMB} -ErrorAction Stop
        Write-Host "Successfully created a new pagefile on C:."
        Write-Host "A REBOOT IS REQUIRED for these changes to take effect." -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to create a new pagefile. Error: $($_.Exception.Message)"
    }
}

Write-Host "Page file size has been configured. A restart is required for the changes to take effect."

# Disable Group Policy: "Accounts: Limit local account use of blank passwords to console logon only"
# This helps with accessing smb file shares from other windows computers on the local network.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 0

# Set secuirty options for SMB sevrer and clients.
# This helps with accessing smb file shares from other windows computers on the local network.
Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false
Set-SmbClientConfiguration -RequireSecuritySignature $false
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force

Restart-Computer -Force