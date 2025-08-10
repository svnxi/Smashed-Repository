# File: FileSecurityTools.psm1
Import-Module AESCryptoHelper

function Protect-FolderAES {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UploadPath,
        [Parameter(Mandatory=$true)]
        [string]$PathToTokens
    )

    # Prepare new log folder if not found
    $logFolder = Join-Path $PathToTokens "Logs"
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }

    # Prepare log file path names
    $errorLog = Join-Path $logFolder "error.log"
    $encryptionLog = Join-Path $logFolder "encryption.log"

    # Collect all contents of Smashed directory
    $uploads = Get-ChildItem -Path $UploadPath -File

    # Additional documentation for extensibility
    $skippedFiles = @()
    $encryptedFiles = @()

    foreach($document in $uploads){
        # Skip unsupported file types
        if ($document.Extension.ToLower() -notin @(".txt", ".csv", ".log", ".xml", ".json", ".html", ".htm", ".md", ".yaml", ".yml", ".ini", ".conf", ".java", ".py", ".js", ".cpp", ".c", ".cs", ".sh", ".ps1", ".bat", ".tsv", ".rtf", ".doc", ".docx")) {
            $prompt = "[WARNING] Skipping unsupported file type: $($document.Name)"
            $log = $prompt
            Write-CustomLog -LogType WARNING -Prompt $prompt -Path $errorLog -Message $log

            $skippedFiles += [PSCustomObject]@{
                FileName = $document.FullName
                Why = $log
            }

            continue
        }

        # Prepare new destination folder for token storage
        $folderName = $document.Name -replace '[^a-zA-Z0-9_\-\.]', '_'
        $tokenPath = Join-Path $PathToTokens $folderName
        if (-not (Test-Path $tokenPath)) { New-Item -Path $tokenPath -ItemType Directory | Out-Null }
            
        # Read uploaded document
        $Contents = Get-Content -Path $document.FullName -Raw
        $byteContents = [System.Text.Encoding]::UTF8.GetBytes($Contents)
        
        # Generate and secure AES-256 compliant Key and IV
        try {
            $keyMaterial = [AESCryptoHelper]::new()
            $keyMaterial.DPAPISave($tokenPath)
        } catch {
            $prompt = "[ERROR] Failed to generate key for $($document.Name): $_"
            $log = $prompt
            Write-CustomLog -LogType ERROR -Prompt $prompt -Path $errorLog -Message $log

            $skippedFiles += [PSCustomObject]@{
                FileName = $document.FullName
                Why = $log
            }

            continue
        }

        # Encrypt contents
        try { $encrypted = $keyMaterial.Encrypt($byteContents) } 
        catch {
            $prompt = "[ERROR] Failed to encrypt $($document.Name): $_"
            Write-CustomLog -LogType ERROR -Prompt $prompt
            continue
        }

        # Save encrypted version to .crypt
        $cryptFate = Join-Path $UploadPath ".crypt"
        if (-not (Test-Path $cryptFate)) { New-Item -Path $cryptFate -ItemType Directory | Out-Null }

        $destFile = Join-Path $cryptFate $document.Name
        [System.IO.File]::WriteAllText($destFile, [Convert]::ToBase64String($encrypted))

        # Log successful output
        $prompt = "[SUCCESS] Encrypted $($document.Name) to $cryptFate"
        $log = "[SUCCESS] Encrypted $($document.Name)"
        Write-CustomLog -LogType HOST -Prompt $prompt -Path $encryptionLog -Message $log

        $encryptedFiles += [PSCustomObject]@{
            OriginalFile = $document.FullName
            EncryptedFile = $destFile
            TokenPath = $tokenPath
        }
    }

    return $encryptedFiles
}

enum LogType {
    HOST = 0
    VERBOSE = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
}

function Write-CustomLog {
    param (
        [Parameter(Mandatory=$true)]
        [LogType]$LogType,
        [string]$Prompt="",
        [string[]]$Tags=@("General"),
        [string]$Path="",
        [string]$Message="",
        [bool]$TimeStamp=$true
    )

    $hasMessage = -not [string]::IsNullOrEmpty($Message)
    $hasPrompt = -not [string]::IsNullOrEmpty($Prompt)
    $didMessage = $false

    switch ($LogType) {
        HOST { if($hasPrompt){ Write-Host $Prompt -ForegroundColor Green}}
        VERBOSE { if($hasPrompt){ Write-Verbose $Prompt } }
        INFO { if($hasPrompt){ Write-Information -MessageData $Prompt -Tags $Tags } }
        WARNING { if($hasPrompt){ Write-Warning $Prompt } }
        ERROR { if($hasPrompt){ Write-Error $Prompt } }
        default { }
    }

    if($hasMessage) {
        if($TimeStamp) { 
            $timeDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $Message = "$($timeDate) - $Message" 
        }
        if(-not [string]::IsNullOrEmpty($Path)) {
            try { 
                Add-Content -Path $Path -Value $Message 
                $didMessage = $true
            }
            catch {
                Write-Warning "Failed to document log: $($_.Exception.Message)"
            }
        } 
        else {
            Write-Host "Failed to log: '($Message)'" -ForegroundColor Gray
            Write-Warning "You intend to write contents with an invalid path."
        }
    }

    return ($hasPrompt -or $didMessage)
}

Export-ModuleMember -Function Protect-FolderAES, Write-CustomLog