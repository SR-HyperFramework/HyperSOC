param(
    [switch]$Create,
    [switch]$Cleanup
)

$TaskName = "AI-SOC-Lab-Benign-Task"
if ($Cleanup) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed lab scheduled task marker if it existed."
    exit 0
}
if ($Create) {
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command Write-Output 'AI SOC lab scheduled task marker'"
    $Trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(10))
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Description "LAB ONLY benign scheduled task telemetry marker" -Force | Out-Null
    Write-Host "Created inert lab scheduled task marker. Run with -Cleanup after validation."
    exit 0
}
Write-Host "LAB ONLY scheduled task marker. Use -Create to create and -Cleanup to remove."
