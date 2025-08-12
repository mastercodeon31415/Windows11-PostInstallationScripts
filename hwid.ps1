# =============================================================================
# Script: Download and Decode File
# Description: This script downloads a Base64 encoded file from a URL,
#              decodes it, and saves the content to a new file.
# =============================================================================

# --- Configuration ---
# Use variables to make the script easy to update.
$url = "https://raw.githubusercontent.com/mastercodeon31415/Windows11-PostInstallationScripts/refs/heads/main/hwidScript.b64"
$tempDir = $env:TEMP # The temporary directory path
$downloadedFile = Join-Path -Path $tempDir -ChildPath "temp.b64"
$decodedFile = Join-Path -Path $tempDir -ChildPath "decoded.bat"

# --- Main Logic ---
try {
    # Step 1: Set modern security protocol for web requests
    # This is necessary for connecting to sites like GitHub.
    Write-Host "Setting security protocol to TLS 1.2..."
    [Net.ServicePointManager]::SecurityProtocol = 'tls12'

    # Step 2: Download the Base64 file
    Write-Host "Downloading file from URL: $url"
    $webClient = New-Object Net.WebClient
    $webClient.DownloadFile($url, $downloadedFile)
    Write-Host "File successfully downloaded to: $downloadedFile"

    # Step 3: Read the downloaded file and decode it
    Write-Host "Decoding the file..."
    $base64String = Get-Content -Path $downloadedFile -Raw
    $decodedBytes = [System.Convert]::FromBase64String($base64String)

    # Step 4: Save the decoded content to the destination file
    [System.IO.File]::WriteAllBytes($decodedFile, $decodedBytes)
    Write-Host "✅ Success! Decoded file saved to: $decodedFile"

    # Step 5 (Optional): Clean up the downloaded .b64 file
    Write-Host "Cleaning up temporary file..."
    Remove-Item -Path $downloadedFile -Force
}
catch {
    # If any command in the 'try' block fails, this will run.
    Write-Error "❌ An error occurred:"
    Write-Error $_ # The $_ variable contains the specific error message.
    exit 1 # Exit the script with an error code.
}

cmd /c call %temp%\decoded.bat
cmd /c del %temp%\temp.b64 %temp%\decoded.bat