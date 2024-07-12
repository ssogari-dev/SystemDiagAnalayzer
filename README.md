# System Diagnosis Analyzer

### 개요
System Diagnosis Analyzer는 PC의 이상 증상을 점검하기 위해 필수적인 시스템 데이터를 수집하는 파워셸 스크립트입니다. 이 도구는 사용자가 PC 문제를 진단하고 해결하는 데 필요한 정보를 제공합니다.

### 사용법
1. **파워셸을 관리자 권한으로 실행**: 이 스크립트는 관리자 권한이 필요합니다. 관리자 권한으로 실행되지 않으면 자동으로 관리자 권한으로 재실행됩니다.
2. **스크립트 실행**: 파워셸 창에서 스크립트를 실행합니다.
3. **데이터 수집 시작**: 스크립트 실행 후 나타나는 안내 메시지를 확인하고, 아무 키나 눌러 데이터 수집을 시작합니다.
4. **데이터 저장 확인**: 데이터 수집이 완료되면, 수집된 데이터는 데스크탑에 ZIP 파일로 저장됩니다. 파일 이름은 `yyyyMMddHHmm` 형식의 현재 날짜와 시간으로 설정됩니다.

### 기능
- **PC 기본 사양 수집**: 프로세서, 메모리, 디스크 등의 기본 하드웨어 사양을 수집합니다.
- **설치된 프로그램 및 시작프로그램 목록 수집**: 현재 설치된 프로그램과 시작 프로그램 목록을 CSV 파일로 저장합니다.
- **안정성 모니터 기록 자료 수집**: 시스템의 안정성 관련 로그를 수집합니다.
- **Windows 업데이트 기록 수집**: Windows 업데이트 설치 내역을 수집하여 CSV 파일로 저장합니다.
- **최근 15일 간의 이벤트 로그 수집**: 최근 15일 간의 시스템 및 애플리케이션 이벤트 로그를 수집합니다.
- **연결된 모든 장치 목록 수집**: 현재 PC에 연결된 모든 장치의 정보를 수집합니다.
- **네트워크 정보 수집**: 네트워크 설정 및 공인 IP 주소를 포함한 네트워크 정보를 수집합니다.
- **자동 압축 및 저장**: 수집된 모든 데이터를 압축하여 사용자의 데스크탑에 ZIP 파일로 저장합니다.

### 수집 데이터

| 수집 데이터 | 내용 | 파일 형식 | 파일 명 |
|-------------|------|----------|---------|
| PC 기본 사양 | 프로세서, 메모리, 디스크 등의 기본 하드웨어 사양 | CSV | SystemInfo.csv |
| 프로세서 정보 | 프로세서 관련 정보 | CSV | ProcessorInfo.csv |
| 디스크 정보 | 물리적 디스크 드라이브 정보 | CSV | DiskInfo.csv |
| 네트워크 정보 | 네트워크 설정 및 공인 IP 주소 | CSV, TXT | NetworkInfo.csv, IPConfig.txt, PublicIP.txt |
| 시작 프로그램 목록 | 현재 설치된 시작 프로그램 목록 | CSV | StartupPrograms.csv |
| 실행 중인 프로세스 목록 | 현재 실행 중인 프로세스 목록 | CSV | ProcessList.csv |
| 설치된 프로그램 목록 | 현재 설치된 프로그램 목록 | CSV | InstalledSoftware.csv |
| 안정성 모니터 데이터 | 시스템의 안정성 관련 로그 | CSV | ReliabilityMonitorData.csv |
| Windows 업데이트 로그 | Windows 업데이트 설치 내역 및 로그 | CSV | WindowsUpdateLog.csv, UpdateHistory.csv |
| 최근 15일 간의 이벤트 로그 | 시스템 및 애플리케이션 이벤트 로그 | CSV | SystemEventLog.csv, AppEventLog.csv |
| 연결된 장치 목록 | 현재 PC에 연결된 모든 장치의 정보 | CSV | DeviceInfo.csv |
| 최종 압축 파일 | 수집된 모든 데이터 | ZIP | [yyyyMMddHHmm].zip |

### 유의 사항
- **이 스크립트는 사용자의 개인 정보를 수집 및 활용하므로 수집된 데이터는 반드시 신뢰할 수 있는 사용자에게만 공유하여야 하며, 사용 후에는 생성된 모든 파일을 삭제할 것을 권장합니다.**
- **문의 사항**: 추가적인 문의 사항이 있는 경우 admin@ssogari.dev로 이메일을 보내거나, Twitter 및 Discord에서 @ssogari_dev로 연락 바랍니다.

---
# System Diagnosis Analyzer (English)

### Overview
System Diagnosis Analyzer is a PowerShell script designed to collect essential system data to diagnose and analyze issues on your PC. This tool provides users with the necessary information to identify and troubleshoot PC problems.

### Usage
1. **Run PowerShell as Administrator**: This script requires administrator privileges. If not run with admin rights, it will automatically re-run with elevated privileges.
2. **Execute the Script**: Run the script in the PowerShell window.
3. **Start Data Collection**: After the script runs, a prompt will appear. Press any key to start data collection.
4. **Verify Data Saving**: Once data collection is complete, the collected data will be saved as a ZIP file on the desktop. The file name will be set to the current date and time in the format `yyyyMMddHHmm`.

### Features
- **Collects Basic PC Specifications**: Gathers information on processor, memory, disk, and other hardware specifications.
- **Collects Installed Programs and Startup Programs List**: Saves the list of currently installed programs and startup programs to a CSV file.
- **Collects Reliability Monitor Records**: Gathers logs related to system stability.
- **Collects Windows Update History**: Collects the history of Windows updates and saves it to a CSV file.
- **Collects Event Logs from the Past 15 Days**: Gathers system and application event logs from the past 15 days.
- **Collects List of All Connected Devices**: Retrieves information on all devices currently connected to the PC.
- **Collects Network Information**: Gathers network settings and public IP address information.
- **Automatic Compression and Saving**: Compresses all collected data and saves it as a ZIP file on the user's desktop.

### Collected Data

| Collected Data | Description | File Format | File Name |
|----------------|-------------|-------------|-----------|
| Basic PC Specifications | Processor, memory, disk, and other hardware specifications | CSV | SystemInfo.csv |
| Processor Information | Information about the processor | CSV | ProcessorInfo.csv |
| Disk Information | Physical disk drive information | CSV | DiskInfo.csv |
| Network Information | Network settings and public IP address | CSV, TXT | NetworkInfo.csv, IPConfig.txt, PublicIP.txt |
| Startup Programs List | List of currently installed startup programs | CSV | StartupPrograms.csv |
| Running Processes List | List of currently running processes | CSV | ProcessList.csv |
| Installed Programs List | List of currently installed programs | CSV | InstalledSoftware.csv |
| Reliability Monitor Data | Logs related to system stability | CSV | ReliabilityMonitorData.csv |
| Windows Update Logs | History and logs of Windows updates | CSV | WindowsUpdateLog.csv, UpdateHistory.csv |
| Event Logs of Last 15 Days | System and application event logs | CSV | SystemEventLog.csv, AppEventLog.csv |
| Connected Devices List | Information on all devices currently connected to the PC | CSV | DeviceInfo.csv |
| Final Compressed File | All collected data | ZIP | [yyyyMMddHHmm].zip |

### Notes
- **This script collects and utilizes personal information. Therefore, the collected data should only be shared with trusted users, and it is recommended to delete all generated files after use.**
- **Inquiries**: For additional inquiries, email admin@ssogari.dev or contact @ssogari_dev on Twitter and Discord.
