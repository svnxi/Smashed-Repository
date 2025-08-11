# AESCryptoHelper.psm1
Add-Type -AssemblyName System.Security
if ($IsWindows -eq $false) {
    throw "DPAPI is only supported on Windows. This module requires Windows OS."
}


# Interface workaround uses a base class inheritance instead
# Linter doesn't pick up the reference so workaround using module member export instead
class CryptoHelperBase {
    [byte[]] Encrypt([byte[]] $data) { 
        throw [System.NotImplementedException]::new("Encrypt method not implemented.") }

    [byte[]] Decrypt([byte[]] $data) { 
        throw [System.NotImplementedException]::new("Decrypt method not implemented.") }
}

# A Proper AES Key Material class
# - Provides a default getter/setter
# - Provides default AES-256
# - Provides option to set encryption level
class AESCryptoHelper : CryptoHelperBase {
    [byte[]]$Key
    [byte[]]$IV

    AESCryptoHelper() {
        $this.Key = New-Object byte[] 32
        $this.IV = New-Object byte[] 16
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($this.Key)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($this.IV)
    }

    AESCryptoHelper([byte[]]$key, [byte[]]$iv) {
        $this.Key = $key
        $this.IV = $iv
    }

    # CORE METHODS
    [byte[]] Encrypt([byte[]] $data) {
        $aes = $this.GetAes()
        $encryptor = $aes.CreateEncryptor()
        return $encryptor.TransformFinalBlock($data, 0, $data.Length)
    }

    [byte[]] Decrypt([byte[]] $data) {
        $aes = $this.GetAes()
        $decryptor = $aes.CreateDecryptor()
        return $decryptor.TransformFinalBlock($data, 0, $data.Length)
    }

    # PERSISTENCE METHODS
    # DPAPI compliant persistence method protects and saves key-IV pair to destination.
    [void] DPAPISave([string]$destinationPath) {
        # Protect key and IV using DPAPI (CurrentUser scope)
        try{
            $protectedKey = [System.Security.Cryptography.ProtectedData]::Protect($this.Key, $null, 'CurrentUser')
            $protectedIV = [System.Security.Cryptography.ProtectedData]::Protect($this.IV, $null, 'CurrentUser')
        }
        catch{
            throw "Failed to protect AES key or iv: $_"
        }

        # Save protected key and IV to disk
        [System.IO.File]::WriteAllBytes($destinationPath+"\aes_key_protected.bin", $protectedKey)
        [System.IO.File]::WriteAllBytes($destinationPath+"\aes_iv_protected.bin", $protectedIV)
    }

    [void] DPAPILoad([string]$sourcePath) {
        # Load protected key and IV from disk
        $protectedKey = [System.IO.File]::ReadAllBytes($sourcePath+"\aes_key_protected.bin")
        $protectedIV = [System.IO.File]::ReadAllBytes($sourcePath+"\aes_iv_protected.bin")

        # Unprotect key and IV (CurrentUser scope)
        $this.Key = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedKey, $null, 'CurrentUser')
        $this.IV = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedIV, $null, 'CurrentUser')
    }

    # UTILITY/HELPER METHODS
    # Initializes an AES object and returns encryptor
    [System.Security.Cryptography.Aes] GetAes([int]$KeySize = 256, [int]$BlockSize = 128) {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = $KeySize
        $aes.BlockSize = $BlockSize
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $this.Key
        $aes.IV = $this.IV
        return $aes
    }
}

# Exporting AESCryptoHelper for external use
Export-ModuleMember -Class AESCryptoHelper