# Run as Administrator Check
if (!([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole] "Administrator")){
    $arguments = "& '" + $myInvocation.MyCommand.Definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Exit
}

# Load Windows Forms Assembly
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------------------------------------------------
# GUI Setup
# ---------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "System Diagnosis Analyzer (SSoGari Dev)"
$form.Size = New-Object System.Drawing.Size(600, 500)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Title Label
$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "PC 시스템 진단용 데이터 수집 도구"
$titleLabel.Font = New-Object System.Drawing.Font("Malgun Gothic", 14, [System.Drawing.FontStyle]::Bold)
$titleLabel.Size = New-Object System.Drawing.Size(560, 30)
$titleLabel.Location = New-Object System.Drawing.Point(20, 15)
$form.Controls.Add($titleLabel)

# Info Label
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "시스템 사양, 이벤트 로그, 오류 드라이버, 서비스 상태 등을 수집하여 바탕화면에 압축 파일로 저장합니다. 수집된 정보는 진단 목적으로만 사용하십시오."
$infoLabel.Size = New-Object System.Drawing.Size(540, 40)
$infoLabel.Location = New-Object System.Drawing.Point(22, 50)
$form.Controls.Add($infoLabel)

# Log Box (Console Output Replacement)
$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ScrollBars = "Vertical"
$logBox.ReadOnly = $true
$logBox.BackColor = "Black"
$logBox.ForeColor = "Lime"
$logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logBox.Location = New-Object System.Drawing.Point(20, 100)
$logBox.Size = New-Object System.Drawing.Size(540, 250)
$form.Controls.Add($logBox)

# Progress Bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(20, 360)
$progressBar.Size = New-Object System.Drawing.Size(540, 25)
$form.Controls.Add($progressBar)

# Start Button
$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = "수집 시작 (Start)"
$startButton.Location = New-Object System.Drawing.Point(150, 400)
$startButton.Size = New-Object System.Drawing.Size(120, 40)
$startButton.BackColor = "LightBlue"
$form.Controls.Add($startButton)

# Exit Button
$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Text = "종료 (Exit)"
$exitButton.Location = New-Object System.Drawing.Point(330, 400)
$exitButton.Size = New-Object System.Drawing.Size(120, 40)
$form.Controls.Add($exitButton)

function Log-Message {
    param([string]$message)
    $logBox.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $message`r`n")
    $logBox.SelectionStart = $logBox.Text.Length
    $logBox.ScrollToCaret()
    $form.Refresh() # Force UI Update
}

$startButton.Add_Click({
    $startButton.Enabled = $false
    $exitButton.Enabled = $false
    $progressBar.Value = 0
    
    $steps = 20
    $stepSize = 100 / $steps
    
    try {
        $directory = "C:\Diag_PC"
        
        # 1. Directory Check
        Log-Message "작업 폴더 확인 중..."
        if(-Not (Test-Path -Path $directory)) {
            New-Item -Path "C:\" -Name "Diag_PC" -ItemType "directory" | Out-Null
            Log-Message "폴더 생성 완료: C:\Diag_PC"
        }
        $progressBar.Value += $stepSize
        
        # 2. Startup Programs
        Log-Message "시작 프로그램 목록 수집 중..."
        $startupPrograms = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
        $startupProgramsList = @()
        foreach ($program in $startupPrograms.PSObject.Properties) {
            $startupProgramsList += [PSCustomObject]@{Name = $program.Name; Value = $program.Value}
        }
        $startupProgramsList | Export-Csv -Path "$directory\StartupPrograms.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 3. Running Processes
        Log-Message "실행 중인 프로세스 수집 중..."
        Get-Process | Select-Object Name, Id, Path, CPU, PM, WS, @{Name="WorkingSet(MB)";Expression={[math]::round($_.WorkingSet64 / 1MB, 2)}}, StartTime | Export-Csv -Path "$directory\ProcessList.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 4. System Info & Disk (Bug Fixed)
        Log-Message "시스템 및 디스크 정보 수집 중..."
        Get-ComputerInfo | Export-Csv -Path "$directory\SystemInfo.csv" -NoTypeInformation -Encoding UTF8
        Get-WmiObject Win32_Processor | Export-Csv -Path "$directory\ProcessorInfo.csv" -NoTypeInformation -Encoding UTF8
        # [Fix] Removed 'ft -Wrap' to save actual data
        Get-PhysicalDisk | Export-Csv -Path "$directory\DiskInfo.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 5. Network Info (Typo Fixed)
        Log-Message "네트워크 정보 수집 중..."
        Get-NetIPConfiguration | Export-Csv -Path "$directory\NetworkInfo.csv" -NoTypeInformation -Encoding UTF8
        ipconfig /all | Out-File -FilePath "$directory\IPConfig.txt"
        try {
            $publicIP = (Invoke-RestMethod http://ipinfo.io/json).ip
            $publicIP | Out-File -FilePath "$directory\PublicIP.txt"
        } catch {
            Log-Message "공인 IP 확인 실패 (인터넷 연결 확인 필요)"
        }
        $progressBar.Value += $stepSize

        # 6. Reliability Monitor
        Log-Message "안정성 모니터 기록 수집 중..."
        Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ReliabilityRecords" | Select-Object SourceName, EventIdentifier, ProductName, Message, TimeGenerated | Export-Csv -Path "$directory\ReliabilityMonitorData.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 7. Windows Update
        Log-Message "Windows 업데이트 기록 수집 중..."
        Get-WmiObject -Class "Win32_QuickFixEngineering" | Select-Object Description, HotFixID, InstalledOn | Export-Csv -Path "$directory\UpdateHistory.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 8. Installed Software
        Log-Message "설치된 소프트웨어 목록 수집 중..."
        Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Export-Csv -Path "$directory\InstalledSoftware.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 9. Event Logs (Recent 15 days)
        Log-Message "최근 15일간 이벤트 로그 수집 중 (시간 소요됨)..."
        $endDate = Get-Date
        $startDate = $endDate.AddDays(-15)
        Get-WinEvent -FilterHashtable @{LogName="System"; StartTime=$startDate; EndTime=$endDate} -ErrorAction SilentlyContinue | Export-Csv -Path "$directory\SystemEventLog.csv" -NoTypeInformation -Encoding UTF8
        Get-WinEvent -FilterHashtable @{LogName="Application"; StartTime=$startDate; EndTime=$endDate} -ErrorAction SilentlyContinue | Export-Csv -Path "$directory\AppEventLog.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 10. Device Info (Basic)
        Log-Message "기본 장치 정보 수집 중..."
        Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, DeviceID, Status | Export-Csv -Path "$directory\DeviceInfo.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 11. Failed PnP Devices (Drivers)
        Log-Message "오류가 있는 드라이버 확인 중..."
        $failedDevices = Get-PnpDevice | Where-Object { $_.Status -eq 'Error' -or $_.Status -eq 'Degraded' -or $_.Status -eq 'Unknown' }
        if ($failedDevices) {
            $failedDevices | Select-Object Status, Class, FriendlyName, InstanceId | Export-Csv -Path "$directory\FailedDevices.csv" -NoTypeInformation -Encoding UTF8
        } else {
            "No Failed Devices Found" | Out-File -FilePath "$directory\FailedDevices.txt"
        }
        $progressBar.Value += $stepSize

        # 12. Windows Services
        Log-Message "Windows 서비스 상태 목록 수집 중..."
        Get-Service | Select-Object Status, Name, DisplayName, StartType | Export-Csv -Path "$directory\ServicesList.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 13. Scheduled Tasks
        Log-Message "작업 스케줄러 목록 수집 중..."
        Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, State, @{Name="NextRunTime";Expression={$_.Triggers.StartBoundary}} | Export-Csv -Path "$directory\ScheduledTasks.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 14. Minidump History
        Log-Message "블루스크린(BSOD) 미니덤프 기록 확인 중..."
        if (Test-Path "C:\Windows\Minidump") {
            Get-ChildItem -Path "C:\Windows\Minidump" | Select-Object Name, CreationTime, LastWriteTime, Length | Export-Csv -Path "$directory\BSOD_History.csv" -NoTypeInformation -Encoding UTF8
        } else {
            "No Minidump Folder found" | Out-File -FilePath "$directory\BSOD_History.txt"
        }
        $progressBar.Value += $stepSize

        # 15. Hosts File
        Log-Message "Hosts 파일 복사 중..."
        if (Test-Path "C:\Windows\System32\drivers\etc\hosts") {
            Copy-Item "C:\Windows\System32\drivers\etc\hosts" -Destination "$directory\hosts.txt"
        }
        $progressBar.Value += $stepSize

        # 16. Battery Report
        Log-Message "배터리 수명 보고서 생성 중..."
        $batteryPath = "$directory\BatteryReport.html"
        powercfg /batteryreport /output "$batteryPath" | Out-Null
        if (-not (Test-Path $batteryPath)) {
            "Battery Report failed or not applicable (Desktop?)" | Out-File -FilePath "$directory\BatteryReport_Log.txt"
        }
        $progressBar.Value += $stepSize

        # 17. Storage Reliability (Detail Disk Health)
        Log-Message "디스크 정밀 건강 상태(S.M.A.R.T) 수집 중..."
        try {
            $diskReliability = Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId, Temperature, ReadErrorsTotal, WriteErrorsTotal, Wear, PowerOnHours
            $diskReliability | Export-Csv -Path "$directory\DiskReliability.csv" -NoTypeInformation -Encoding UTF8
        } catch {
            Log-Message "디스크 정밀 정보 수집 실패 (권한 또는 지원하지 않는 드라이버)"
        }
        $progressBar.Value += $stepSize

        # 18. Antivirus Status
        Log-Message "Windows Defender 상태 확인 중..."
        try {
            Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, AMServiceEnabled | Export-Csv -Path "$directory\SecurityStatus.csv" -NoTypeInformation -Encoding UTF8
        } catch {
            Log-Message "Defender 확인 실패"
        }
        $progressBar.Value += $stepSize

        # 19. Environment Variables
        Log-Message "시스템 환경 변수(PATH 등) 수집 중..."
        Get-ChildItem Env: | Select-Object Name, Value | Export-Csv -Path "$directory\EnvironmentVariables.csv" -NoTypeInformation -Encoding UTF8
        $progressBar.Value += $stepSize

        # 20. Compression
        Log-Message "데이터 압축 중..."
        $zipFileName = "PC_Diagnosis_$(Get-Date -Format 'yyyyMMddHHmm').zip"
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $zipFilePath = Join-Path -Path $desktopPath -ChildPath $zipFileName
        if(Test-Path $zipFilePath) { Remove-Item $zipFilePath }
        Compress-Archive -Path "$directory\*" -DestinationPath $zipFilePath
        $progressBar.Value = 100
        
        Log-Message "-----------------------------------"
        Log-Message "모든 작업이 완료되었습니다."
        Log-Message "파일 저장 위치: $zipFilePath"
        
        [System.Windows.Forms.MessageBox]::Show("진단 데이터 수집이 완료되었습니다.`n바탕화면에 ZIP 파일이 생성되었습니다.", "완료", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        
        # Cleanup Folder (Optional - Uncomment if needed)
        # Remove-Item -Path $directory -Recurse -Force

    } catch {
        Log-Message "오류 발생: $_"
        [System.Windows.Forms.MessageBox]::Show("작업 중 오류가 발생했습니다.`n$_", "오류", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    } finally {
        $startButton.Enabled = $true
        $exitButton.Enabled = $true
    }
})

$exitButton.Add_Click({
    $form.Close()
})

# Show Form
$form.ShowDialog() | Out-Null
