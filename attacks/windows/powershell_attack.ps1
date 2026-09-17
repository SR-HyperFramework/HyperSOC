<#
LAB ONLY: benign PowerShell telemetry marker.
This writes a Windows Event Log marker and prints environment context. It does not
download payloads, bypass policy, or execute arbitrary code.
#>

$Source = "AI-SOC-Lab"
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    New-EventLog -LogName Application -Source $Source
}
Write-EventLog -LogName Application -Source $Source -EntryType Information -EventId 1059 -Message "LAB ONLY PowerShell telemetry marker for T1059.001 detection validation"
Write-Host "LAB ONLY PowerShell telemetry marker written."
