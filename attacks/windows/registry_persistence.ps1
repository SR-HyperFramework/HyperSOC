param(
    [switch]$Create,
    [switch]$Cleanup
)

$Path = "HKCU:\Software\AI-SOC-Lab"
$Name = "BenignRunKeyMarker"
if ($Cleanup) {
    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    Write-Host "Removed lab registry marker if it existed."
    exit 0
}
if ($Create) {
    New-Item -Path $Path -Force | Out-Null
    Set-ItemProperty -Path $Path -Name $Name -Value "LAB ONLY benign registry telemetry marker"
    Write-Host "Created benign HKCU registry marker. Run with -Cleanup after validation."
    exit 0
}
Write-Host "LAB ONLY registry marker. Use -Create to write and -Cleanup to remove."
