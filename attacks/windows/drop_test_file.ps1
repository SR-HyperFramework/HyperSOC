param(
    [string]$Path = "$env:TEMP\ai-soc-lab-fim-marker.txt",
    [switch]$Cleanup
)

if ($Cleanup) {
    Remove-Item -Path $Path -ErrorAction SilentlyContinue
    Write-Host "Removed lab FIM marker if it existed: $Path"
    exit 0
}
"AI SOC LAB ONLY FIM marker $(Get-Date -Format o)" | Set-Content -Path $Path -Encoding UTF8
Get-FileHash -Algorithm SHA256 -Path $Path | Format-List
Write-Host "Created harmless FIM marker: $Path"
