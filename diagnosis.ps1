# Run as Administrator
if (!([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole] "Administrator")){
    $arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Exit
}

# 화면에 출력하는 내용
$text = @"
┌───────────────────────────────────────────────────────────────────────────┐
│                            System Diagnosis Analyzer                      │
│                             ( SSoGari Dev. Studio )                       │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  이 프로그램은 PC 이상 증상 점검을 위한 기초적인 데이터 수집을 진행합니다 │
│                                                                           │
│   수집되는 데이터는 아래와 같습니다.                                      │
│    - PC 기본 사양 (프로세서, 메모리, 디스크 등)                           │
│    - 설치된 프로그램 및 시작프로그램 목록                                 │
│    - 안정성 모니터 기록 자료                                              │
│    - Windows 업데이트 기록                                                │
│    - 최근 15일 간 이벤트 기록                                             │
│    - 연결된 모든 장치 목록                                                │
│                                                                           │
│   개인정보를 포함한 수집된 모든 자료는 점검 및 상담 이후 복구가           │
│   불가능하도록 삭제됩니다.                                                │
│                                                                           │
│   위 내용에 모두 동의하시면 아무 키나 눌러 수집을 진행하여 주십시오.      │
│   동의하지 않으신다면 프로그램을 즉시 종료하고 삭제하여 주시기 바랍니다.  │
├───────────────────────────────────────────────────────────────────────────┤
│   Contact: admin@ssogari.dev / Twitter & Discord @ssogari_dev             │
└───────────────────────────────────────────────────────────────────────────┘

"@

# 내용 출력
Write-Host $text

# 사용자 입력 대기
Read-Host -Prompt "Press Enter to Start"

Clear-Host
# Write-Host ""
# Write-Host ""
Write-Output "[ ? ] Preparing the Collecting Data"
# Check Directory and Create if it does not exist
$directory = "C:\Diag_PC"
Write-Output "[ ! ] Check the Directory (C:\Diag_PC)"
if(-Not (Test-Path -Path $directory)) {
    New-Item -Path "C:\" -Name "Diag_PC" -ItemType "directory"
    Write-Output "[ ! ] Not Exist. Create the New Directory"
}

# 5-1. Check Startup List (CSV)
Write-Output "[ ! ] Collecting Startup Process List"
$startupPrograms = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
$startupProgramsList = @()
foreach ($program in $startupPrograms.PSObject.Properties) {
    $startupProgramsList += [PSCustomObject]@{
        Name = $program.Name
        Value = $program.Value
    }
}
$startupProgramsList | Export-Csv -Path "C:\Diag_PC\StartupPrograms.csv" -NoTypeInformation -Encoding UTF8

# 5-2. Check Process List (CSV)
Write-Output "[ ! ] Collecting Running Process List"
$processList = Get-Process | Select-Object Name, Id, Path, CPU, PM, WS, @{Name="WorkingSet(MB)";Expression={[math]::round($_.WorkingSet64 / 1MB, 2)}}, StartTime
$processList | Export-Csv -Path "C:\Diag_PC\ProcessList.csv" -NoTypeInformation -Encoding UTF8

# 5-3. System Information
Write-Output "[ ! ] Collecting System Information"
$systemInfo = Get-ComputerInfo
$systemInfoList = @()
foreach ($property in $systemInfo.PSObject.Properties) {
    $systemInfoList += [PSCustomObject]@{
        Name = $property.Name
        Value = $property.Value
    }
}
$systemInfoList | Export-Csv -Path "C:\Diag_PC\SystemInfo.csv" -NoTypeInformation -Encoding UTF8
Write-Output "[ ! ] Writing Processor Information"
$processorInfo = Get-WmiObject Win32_Processor
$processorInfo | Export-Csv -Path "C:\Diag_PC\ProcessorInfo.csv" -NoTypeInformation -Encoding UTF8
Write-Output "[ ! ] Checking Physical Disk Drive Information"
$diskInfo = Get-PhysicalDisk |ft -Wrap
$diskInfo | Export-Csv -Path "C:\Diag_PC\DiskInfo.csv" -NoTypeInformation -Encoding UTF8

# 5-4. Network Information
Write-Output "[ ! ] Collecting Network Information"
$networkInfo = Get-NetIPConfiguration
$networkInfo | Export-Csv -Path "C:\Diag_PC\NetworkInfo.csv" -NoTypeInformation -Encoding UTF8

$ipconfig = ipconfig /all
$ipconfig | Out-File -FilePath "$directory\IPConfig.txt"

function Get-Public {
    try {
        $publicIP = (Invoke-RestMethod http://ipinfo.io/json).ip
        $publicIP | Out-File -FilePath "C:\Diag_PC\PublicIP.txt"
        return $publicIP
    } catch {
        wirite-Error "[ ! ] Can not get Public IP: $_"
    }
}
$publicIp = Get-Public
if($publicIp) {
    $publicIp | Out-File -FilePath "C:\Diag_PC\PublicIP.txt"
}

# 5-5. Reliablity Monitor Data (CSV)
Write-Output "[ ! ] Collecting Reliablity Monitor Data"
$reliabilityData = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ReliabilityRecords"
$reliabilityData | Select-Object SourceName, EventIdentifier, ProductName, Message, TimeGenerated | Export-Csv -Path "$directory\ReliabilityMonitorData.csv" -NoTypeInformation -Encoding UTF8

# 5-6. Memory Dump Data (CSV)
# $memoryDumpEventsSystem = Get-WinEvent -LogName "System" -FilterHashtable @{ProviderName="Microsoft-Windows-WER-Diagnostics"} -MaxEvents 1000
# $memoryDumpEventsSystem | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path "$directory\MemoryDumpEventsSystem.csv" -NoTypeInformation -Encoding UTF8
# 
# $memoryDumpEventsApplication = Get-WinEvent -LogName "Application" -FilterHashtable @{ProviderName="Application Error"} -MaxEvents 1000
# $memoryDumpEventsApplication | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -Path "$directory\MemoryDumpEventsApplication.csv" -NoTypeInformation -Encoding UTF8

# 5-7. Windows Update Log
Write-Output "[ ! ] Collecting Windows Update Log"
$windowsUpdateLog = Get-WinEvent -ProviderName Microsoft-Windows-WindowsUpdateClient
$windowsUpdateLog | Export-Csv -Path "C:\Diag_PC\WindowsUpdateLog.csv" -NoTypeInformation -Encoding UTF8
$updateHistory = Get-WmiObject -Class "Win32_QuickFixEngineering" | Select-Object -Property "Description", "HotFixID", "InstalledOn"
$updateHistory | Export-Csv -Path "C:\Diag_PC\UpdateHistory.csv" -NoTypeInformation -Encoding UTF8

# 5-8. Installed Software
Write-Output "[ ! ] Collecting Installed Software List"
$installedSoftware = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
$installedSoftware | Export-Csv -Path "C:\Diag_PC\InstalledSoftware.csv" -NoTypeInformation -Encoding UTF8

# 5-9. Event Viewer Log in 15 days
Write-Output "[ ! ] Collecting Event of Software and System"
$endDate = Get-Date
$startDate = $endDate.AddDays(-15)
Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=$startDate; EndTime=$endDate} | Export-Csv -Path "C:\Diag_PC\SystemEventLog.csv" -NoTypeInformation -Encoding UTF8
Get-WinEvent -FilterHashtable @{LogName="Application"; StartTime=$startDate; EndTime=$endDate} | Export-Csv -Path "C:\Diag_PC\AppEventLog.csv" -NoTypeInformation -Encoding UTF8

# 5-10. Device Information
Write-Output "[ ! ] Collecting Device Information"
$deviceInfo = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, DeviceID, Status
$deviceInfo | Export-Csv -Path "C:\Diag_PC\DeviceInfo.csv" -NoTypeInformation -Encoding UTF8

Write-Output "[ ! ] Compressing the collected data"
$zipFileName = "$(Get-Date -Format 'yyyyMMddHHmm').zip"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$zipFilePath = Join-Path -Path $desktopPath -ChildPath $zipFileName
$sourcePath = "C:\Diag_PC"
Compress-Archive -Path $sourcePath -DestinationPath $zipFilePath

Read-Host -Prompt "Complete. Data File saved at Desktop"
