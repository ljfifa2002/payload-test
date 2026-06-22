# Generate a 32-byte CSPRNG key. Prints Java array literals for
# Obf.java (byte[]) and StringObfFactory.java (int[]). ASCII only on purpose:
# Windows PowerShell 5.1 misreads UTF-8 comments under a GBK codepage.

$bytes = New-Object 'byte[]' 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$hex = $bytes | ForEach-Object { '0x{0:X2}' -f $_ }

$lines = @()
$lines += '=== Obf.java KEY (byte[]) ==='
for ($i = 0; $i -lt 32; $i += 8) { $lines += '        ' + (($hex[$i..($i+7)] | ForEach-Object { "(byte)$_" }) -join ',') + ',' }
$lines += ''
$lines += '=== StringObfFactory.java KEY (int[]) ==='
for ($i = 0; $i -lt 32; $i += 8) { $lines += '        ' + (($hex[$i..($i+7)]) -join ',') + ',' }

# Print to console
$lines | ForEach-Object { Write-Host $_ }

# Also save next to the script so it is always copyable
$outFile = Join-Path $PSScriptRoot 'obf-key-output.txt'
$lines | Set-Content -Path $outFile -Encoding ascii
Write-Host ''
Write-Host "Saved to: $outFile"

# Keep the window open (no auto-close on double-click)
Write-Host ''
Read-Host 'Done. Press Enter to close'
