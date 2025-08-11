Import-Module FileSecurityTools

# For Portability - use if you want the script to work relative to its location (regardless of right-click run)
$currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Prepare upload path for input files
$smashedFolder = Join-Path $currentDir "Smashed"
if (-not (Test-Path $smashedFolder)) { New-Item -Path $smashedFolder -ItemType Directory | Out-Null }

# Prepare storage path for protected data (better on separate drive)
$tokenStore = Join-Path $currentDir "Secret"
if (-not (Test-Path $tokenStore)) { New-Item -Path $tokenDir -ItemType Directory | Out-Null }

Protect-FolderAES -UploadPath $smashedFolder -PathToTokens $tokenStore



