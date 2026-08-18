# 워크스테이션 보안 점검 스크립트

Windows 워크스테이션과 그 안의 WSL 환경에서 아래 3가지를 점검한다.

1. **SSH 개인키에 passphrase가 걸려 있는지** (GitHub / GX-10 접속용 키 포함)
2. **디스크 암호화 여부** (BitLocker / Device Encryption, WSL vhdx 포함)
3. **`~/.ssh` 가 NAS 백업이나 클라우드 동기화 대상에 포함되는지**

두 스크립트 모두 **조회만 수행하며 시스템을 변경하지 않는다.** 키 파일의 내용이나
자격증명 값은 출력하지 않고, 파일명·지문(fingerprint)·경로만 표시한다.

---

## 실행 방법

Windows 측과 WSL 측은 **완전히 별개의 `~/.ssh` 를 가진다.** 둘 다 실행해야 점검이 끝난다.

### 1) Windows (PowerShell)

```powershell
cd <저장소 경로>\tools\security-check
powershell -ExecutionPolicy Bypass -File .\Check-WorkstationSecurity.ps1
```

BitLocker 상태는 관리자 권한에서 더 정확하게 조회된다. 일반 권한으로 실행해
`[WARN] BitLocker 상태를 API로 확인하지 못함` 이 나오면 관리자 PowerShell 로 다시 실행할 것.

### 2) WSL (bash)

```bash
cd <저장소 경로>/tools/security-check
bash check-wsl-security.sh
```

WSL 안에서 실행하면 interop(`powershell.exe`)을 통해 Windows BitLocker 상태도 함께 조회한다.
FAIL 항목이 하나라도 있으면 종료 코드 1 을 반환하므로 CI 나 스크립트에서 사용할 수 있다.

---

## 판정 기준

| 표시 | 의미 |
| --- | --- |
| `PASS` | 안전한 상태로 확인됨 |
| `WARN` | 위험 가능성이 있거나, 자동 확인이 불가해 직접 확인이 필요함 |
| `FAIL` | 즉시 조치가 필요한 상태 |
| `INFO` | 판단 근거가 되는 참고 정보 |

### 1. passphrase 판별 방식

`ssh-keygen` 의 종료 코드에만 의존하면 **파일 권한 문제(0644 등)를 "암호화됨"으로 오판**한다.
그래서 이 스크립트는 파일 포맷을 직접 읽어 판별하고, 포맷으로 판별되지 않을 때만
`ssh-keygen` 을 보조로 사용한다.

| 포맷 | 판별 근거 |
| --- | --- |
| OpenSSH (`BEGIN OPENSSH PRIVATE KEY`) | base64 헤더의 ciphername (`none` = 무암호, `aes256-ctr` 등 = 암호화) |
| PEM (`Proc-Type: 4,ENCRYPTED` / `DEK-Info`) | 헤더 존재 여부 |
| PKCS#8 | `BEGIN ENCRYPTED PRIVATE KEY` = 암호화, `BEGIN PRIVATE KEY` = 무암호 |
| PuTTY `.ppk` | `Encryption:` 필드 |

OpenSSH / PEM(암호화·평문) / PKCS#8(암호화·평문) 6종 실제 키로 두 스크립트 모두 검증했다.

### 2. 디스크 암호화와 WSL의 관계

WSL2 의 홈 디렉터리는 `%LOCALAPPDATA%\Packages\<배포판>\LocalState\ext4.vhdx` 안에 있다.
**WSL 자체에는 별도의 암호화 계층이 없으므로, WSL 안의 `~/.ssh` 가 저장 시 암호화되는지는
그 vhdx 가 놓인 Windows 볼륨의 BitLocker 상태를 그대로 따른다.**
C: 드라이브가 BitLocker 로 보호되지 않으면 WSL 안의 키도 평문으로 디스크에 남는다.

### 3. 백업 / 동기화 노출 점검 범위

자동으로 확인하는 것:

- `.ssh` 경로가 OneDrive / Dropbox / Google Drive / Synology Drive / Nextcloud 등
  동기화 루트 **하위에 있는지**
- `.ssh` 가 심볼릭 링크·정션으로 동기화 폴더를 가리키는지
- 동기화 폴더 안에 `id_rsa`, `id_ed25519`, `*.pem`, `*.ppk`, `*.key` **사본이 흩어져 있는지**
- WSL 홈이나 `.ssh` 가 `/mnt/c` 등 Windows 파일시스템 위에 있는지
- 마운트된 NAS(NFS/SMB/sshfs), 매핑된 네트워크 드라이브
- 백업 에이전트(Veeam, Acronis, Synology Drive, Duplicati, restic, borg, rclone 등) 설치 여부
- `.ssh` 나 복사 도구(rsync/robocopy/rclone 등)를 호출하는 cron / systemd timer / 예약 작업
- Windows 파일 기록(File History) 구성 여부
- 저장소에 키 파일이 커밋되어 있는지, `~/.git-credentials` 등 평문 토큰 존재 여부

**자동으로 판정할 수 없는 것:** NAS 백업 소프트웨어의 *잡(job) 대상 경로 선택*.
스크립트는 백업 에이전트가 설치되어 있으면 `WARN` 으로 알려주며, 해당 제품의 백업 대상에
사용자 프로필(`%USERPROFILE%`)이나 WSL vhdx 가 포함되는지는 직접 확인해야 한다.

---

## FAIL 이 나왔을 때의 조치

**passphrase 없는 키**

```bash
# 기존 키에 passphrase 추가 (키 자체는 그대로 유지되므로 GitHub 재등록 불필요)
ssh-keygen -p -f ~/.ssh/id_ed25519
```

키 파일이 이미 유출되었을 가능성이 있다면 passphrase 추가로는 부족하다.
새 키를 만들고 GitHub 및 GX-10 의 `authorized_keys` 에서 기존 공개키를 제거할 것.

매번 passphrase 입력이 번거로우면 ssh-agent 를 쓴다.

```bash
# WSL: 셸 시작 시 agent 기동 후 키 등록
eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519
```

```powershell
# Windows: ssh-agent 서비스 자동 시작 후 키 등록
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```

**키 파일 권한이 느슨함**

```bash
chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_*    # WSL
```

```powershell
icacls $env:USERPROFILE\.ssh /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"   # Windows
```

**BitLocker 꺼짐** — 설정 → 개인 정보 및 보안 → 장치 암호화, 또는 관리자 PowerShell 에서
`Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly`.
복구 키는 반드시 별도 안전한 곳에 보관할 것.

**동기화 폴더에 키 사본 발견** — 해당 파일을 삭제하는 것만으로는 부족하다.
클라우드 서비스의 **휴지통·버전 기록에도 남아 있으므로** 함께 지우고,
그 키는 유출된 것으로 간주해 회수(GitHub/서버에서 공개키 제거)한 뒤 새 키로 교체할 것.
