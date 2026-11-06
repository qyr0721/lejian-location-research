# encrypt_blacklist.ps1
# Encrypt the blacklist plaintext into app/src/release/assets/blacklist.enc
#
# File spec (must match the Android reader exactly):
#   Algorithm : AES/CBC/PKCS5Padding  (.NET: PKCS7, identical for 16-byte blocks)
#   Key       : FLblkey2026@1234      (UTF-8 bytes, 16 chars -> AES-128)
#   IV        : FLbliv2026@12345      (UTF-8 bytes, 16 chars)
#   Encoding  : single-line Base64, no line breaks, no BOM, no trailing newline
#
# Usage:
#   powershell -File tools/encrypt_blacklist.ps1
#   powershell -File tools/encrypt_blacklist.ps1 -PlaintextPath blacklist.txt -OutputPath app/src/release/assets/blacklist.enc
#
param(
    [string]$PlaintextPath = "blacklist.txt",
    [string]$OutputPath    = "app/src/release/assets/blacklist.enc"
)

$ErrorActionPreference = "Stop"

$Key = [System.Text.Encoding]::UTF8.GetBytes("FLblkey2026@1234")
$Iv  = [System.Text.Encoding]::UTF8.GetBytes("FLbliv2026@12345")

if ($Key.Length -ne 16) { throw "Key must be 16 bytes after UTF-8 encoding." }
if ($Iv.Length  -ne 16) { throw "IV must be 16 bytes after UTF-8 encoding." }

if (-not (Test-Path -LiteralPath $PlaintextPath)) {
    throw "Plaintext file not found: $PlaintextPath"
}

# Read plaintext as raw bytes: do NOT add or strip anything,
# comments (#) and line endings are preserved as-is.
$plain = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $PlaintextPath))

$aes = [System.Security.Cryptography.Aes]::Create()
try {
    $aes.Mode        = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding     = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize     = 128
    $aes.BlockSize   = 128
    $aes.Key         = $Key
    $aes.IV          = $Iv

    $encryptor = $aes.CreateEncryptor()
    try {
        $cipher = $encryptor.TransformFinalBlock($plain, 0, $plain.Length)
    } finally {
        $encryptor.Dispose()
    }
} finally {
    $aes.Dispose()
}

# Single-line Base64, written without BOM and without trailing newline.
$b64 = [Convert]::ToBase64String($cipher)
$enc = New-Object System.Text.UTF8Encoding($false)
$outFull = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllText($outFull, $b64, $enc)

Write-Host ("Encrypted OK: {0} bytes plaintext -> {1} bytes cipher -> {2} Base64 chars" -f $plain.Length, $cipher.Length, $b64.Length)
Write-Host "Output: $outFull"
