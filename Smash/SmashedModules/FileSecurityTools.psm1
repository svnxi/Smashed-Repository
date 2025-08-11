# File: FileSecurityTools.psm1
if (-not (Get-Module -ListAvailable -Name AESCryptoHelper)) {
    Write-Error "Required module 'AESCryptoHelper' is not available."
    return
}

Import-Module AESCryptoHelper

enum LogType {
    HOST = 0
    VERBOSE = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
}

function Write-CustomLog {
    [CmdletBinding()]
    param (
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
                Write-Warning "[PATH] Failed to document log: $($_.Exception.Message)"
            }
        } 
        else {
            Write-Host "Failed to log: '($Message)'" -ForegroundColor Gray
            Write-Warning "You intend to write contents with an invalid path."
        }
    }
}

function Confirm-SupportedFileType {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Extension
    )

    $supported = @(".txt", ".csv", ".log", ".xml", ".json", ".html", ".htm", ".md", ".yaml", ".yml", ".ini", ".conf", ".java", ".py", ".js", ".cpp", ".c", ".cs", ".sh", ".ps1", ".bat", ".tsv", ".rtf", ".doc", ".docx")
    return $supported -contains $Extension.ToLower()
}

function Get-SmashedFiles {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DirectoryPath,
        [int]$Limit=5
    )

    $uploads = Get-ChildItem -Path $DirectoryPath -File
    if($uploads.Length -gt $Limit) {
        $prompt = "You can upload a maximum of $Limit files."
        Write-CustomLog -LogType WARNING -Prompt $prompt
        return @()
    }

    return $uploads
}

function Protect-FolderAES {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$UploadPath,
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$PathToTokens,
        [Parameter()]
        [int]$MaxFiles = 10
    )

    # Prepare new log folder if not found
    $logFolder = Join-Path $PathToTokens "Logs"
    if (-not (Test-Path $logFolder)) { New-Item -Path $logFolder -ItemType Directory | Out-Null }

    # Prepare log file path names
    $errorLog = Join-Path $logFolder "error.log"
    $successLog = Join-Path $logFolder "success.log"

    # Collect all contents of Smashed directory (validate if null or empty)
    $uploads = Get-SmashedFiles -DirectoryPath $UploadPath -Limit $MaxFiles
    if(-not $uploads -or $uploads.Count -eq 0) { return } 

    # Save additional documentation for extensibility
    $skippedFiles = @()
    $encryptedFiles = @()

    foreach($document in $uploads){
        # Skip unsupported file types
        if (-not (Confirm-SupportedFileType -Extension $document.Extension)) {
            $prompt = "[WARNING] Skipping unsupported file type: $($document.Name)"
            $log = $prompt
            Write-CustomLog -LogType WARNING -Prompt $prompt -Path $errorLog -Message $log

            $skippedFiles += [PSCustomObject]@{
                FileName = $document.FullName
                Why = "Unsupported Type"
            }

            continue
        }

        # Prepare new destination folder for token storage
        $folderName = $document.Name -replace '[^a-zA-Z0-9_\-\.]', '_'
        $tokenPath = Join-Path $PathToTokens $folderName
        if (-not (Test-Path $tokenPath)) { New-Item -Path $tokenPath -ItemType Directory | Out-Null }
            
        # Read uploaded document and convert to byte format
        $Contents = Get-Content -Path $document.FullName -Raw
        $byteContents = [System.Text.Encoding]::UTF8.GetBytes($Contents)
        
        # Generate and secure AES-256 compliant Key and IV
        try {
            $keyMaterial = [AESCryptoHelper]::new()
            $keyMaterial.DPAPISave($tokenPath)
        } catch {
            $prompt = "[ERROR] Failed to generate key for $($document.Name): $($_.Exception.Message)"
            $log = $prompt
            Write-CustomLog -LogType ERROR -Prompt $prompt -Path $errorLog -Message $log

            $skippedFiles += [PSCustomObject]@{
                FileName = $document.FullName
                Why = "Fatal Error"
            }

            continue
        }

        # Encryption
        try { $encrypted = $keyMaterial.Encrypt($byteContents) } 
        catch {
            $prompt = "[ERROR] Failed to encrypt $($document.Name): $($_.Exception.Message)"
            $log = $prompt
            Write-CustomLog -LogType ERROR -Prompt $prompt -Path $errorLog -Message $log
            continue
        }

        # Save encrypted version to .crypt
        $cryptFate = Join-Path $UploadPath ".crypt"
        if (-not (Test-Path $cryptFate)) { New-Item -Path $cryptFate -ItemType Directory | Out-Null }

        $destFile = Join-Path $cryptFate $document.Name
        [System.IO.File]::WriteAllText($destFile, [Convert]::ToBase64String($encrypted))

        # Log successful output
        $prompt = "[SUCCESS] Encrypted $($document.Name) to secret folder"
        $log = $prompt
        Write-CustomLog -LogType HOST -Prompt $prompt -Path $successLog -Message $log

        $encryptedFiles += [PSCustomObject]@{
            OriginalFile = $document.FullName
            EncryptedFile = $destFile
            TokenPath = $tokenPath
        }
    }

    $prompt = "Encrypted:$($encryptedFiles.Length)\nSkipped:$($skippedFiles.Length)"
    $log = $prompt
    Write-CustomLog -LogType VERBOSE -Prompt $prompt -Path $successLog -Message $log -TimeStamp $false

    return [PSCustomObject]@{
        Timestamp = (Get-Date)
        TotalProcessed = $uploads.Count
        EncryptedCount = $encryptedFiles.Count
        SkippedCount = $skippedFiles.SkippedCount
        EncryptedFiles = $encryptedFiles
        SkippedFiles = $skippedFiles
    }
}

# Exporting Protect-FolderAES for external use
Export-ModuleMember -Function Protect-FolderAES