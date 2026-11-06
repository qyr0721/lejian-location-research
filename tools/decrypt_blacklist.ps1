# decrypt_blacklist.ps1
# Decrypt app/src/release/assets/blacklist.enc back to plaintext for review/edit.
#
# File spec (must match the Android reader exactly):
#   Algorithm : AES/CBC/PKCS5Padding  (.NET: PKCS7, identical for 16-byte blocks)
#   Key       : FLblkey2026@1234      (UTF-8 bytes, 16 chars -> AES-128)
#   IV        : FLbliv2026@12345      (UTF-8 bytes, 16 chars)
#   Encoding  : single-line Base64, no line breaks, no BOM, no trailing newline
#
# Usage:
#   powershell -File tools/decrypt_blacklist.ps1 -InputPath app/src/release/assets/blacklist.enc -OutputPath blacklist.txt
#
param(
    [string]$InputPath  = "app/src/release/assets/blacklist.enc",
    [string]$OutputPath = "blacklist.txt"
)

$ErrorActionPreference = "Stop"

$Key = [System.Text.Encoding]::UTF8.GetBytes("FLblkey2026@1234")
$Iv  = [System.Text.Encoding]::UTF8.GetBytes("FLbliv2026@12345")

if ($Key.Length -ne 16) { throw "Key must be 16 bytes after UTF-8 encoding." }
if ($Iv.Length  -ne 16) { throw "IV must be 16 bytes after UTF-8 encoding." }

if (-not (Test-Path -LiteralPath $InputPath)) {
    throw "Encrypted file not found: $InputPath"
}

# Read the whole file, trim any whitespace/newlines defensively, then Base64-decode.
$raw = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $InputPath)).Trim()
$cipher = [Convert]::FromBase64String($raw)
if ($cipher.Length % 16 -ne 0) {
    throw "Invalid ciphertext length ($($cipher.Length) bytes), not a multiple of the AES block size."
}

$aes = [System.Security.Cryptography.Aes]::Create()
try {
    $aes.Mode        = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding     = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize     = 128
    $aes.BlockSize   = 128
    $aes.Key         = $Key
    $aes.IV          = $Iv

    $decryptor = $aes.CreateDecryptor()
    try {
        $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
    } finally {
        $decryptor.Dispose()
    }
} finally {
    $aes.Dispose()
}

# Write plaintext bytes as-is (no BOM, no trailing newline added).
$outFull = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $outFull
if (-not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllBytes($outFull, $plain)

Write-Host ("Decrypted OK: {0} Base64 chars -> {1} bytes cipher -> {2} bytes plaintext" -f $raw.Length, $cipher.Length, $plain.Length)
Write-Host "Output: $outFull"
