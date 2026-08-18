<#
.SYNOPSIS
    Windows 워크스테이션 SSH 키 / 디스크 암호화 / 백업·동기화 노출 점검 (읽기 전용).

.DESCRIPTION
    아래 3가지를 점검한다. 시스템을 변경하지 않으며 조회만 수행한다.
      1) SSH 개인키에 passphrase가 걸려 있는지
      2) 디스크 암호화(BitLocker / Device Encryption) 상태
      3) ~/.ssh 가 클라우드 동기화 / NAS 백업 경로에 포함되는지

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Check-WorkstationSecurity.ps1

.NOTES
    BitLocker 상태는 관리자 권한에서 더 정확하게 조회된다.
#>

[CmdletBinding()]
param(
    [string]$SshDir = (Join-Path $env:USERPROFILE '.ssh')
)

$ErrorActionPreference = 'Continue'
$script:Findings = @()

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkGray
}

function Add-Finding {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Level,
        [string]$Area,
        [string]$Message
    )
    $script:Findings += [pscustomobject]@{ Level = $Level; Area = $Area; Message = $Message }
    $color = switch ($Level) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Gray' }
    }
    Write-Host ("  [{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Get-PrivateKeyEncryptionState {
    <#
      개인키가 passphrase 로 암호화되어 있는지 파일 포맷으로 판별한다.
      ssh-keygen 의 종료 코드에만 의존하면 파일 권한 문제를 "암호화됨"으로 오판하므로
      포맷 검사를 1차로 쓰고, 판별 불가일 때만 ssh-keygen 으로 보조 확인한다.
      반환: @{ State = 'Encrypted'|'Plaintext'|'Unknown'; Format = ...; Detail = ... }
    #>
    param([string]$Path, [string]$KeygenPath)

    $result = @{ State = 'Unknown'; Format = 'unknown'; Detail = '' }
    $lines = Get-Content -LiteralPath $Path -TotalCount 6 -ErrorAction SilentlyContinue
    if (-not $lines) { return $result }
    $head = $lines -join "`n"

    if ($head -match 'BEGIN OPENSSH PRIVATE KEY') {
        $result.Format = 'openssh'
        try {
            $raw = Get-Content -LiteralPath $Path -Raw
            $b64 = ($raw -replace '-----[^-]*-----', '') -replace '\s', ''
            $bytes = [Convert]::FromBase64String($b64)
            $take = [Math]::Min(64, $bytes.Length)
            $text = [Text.Encoding]::ASCII.GetString($bytes, 0, $take)
            # 헤더에는 NUL/개행 등 제어문자가 섞여 있어 정규식 '.' 가 걸리지 않는다.
            # 비출력 문자를 '.' 로 치환해 한 줄로 만든 뒤 매칭한다.
            $text = [Regex]::Replace($text, '[^\x20-\x7E]', '.')
            # 구조: "openssh-key-v1\0" + uint32 길이 + ciphername
            if ($text -match 'openssh-key-v1.*none') {
                $result.State = 'Plaintext'; $result.Detail = 'cipher=none'
            } elseif ($text -match 'openssh-key-v1.*(aes[0-9]*-[a-z]+|3des-cbc|chacha20-poly1305\S*)') {
                $result.State = 'Encrypted'; $result.Detail = "cipher=$($Matches[1])"
            }
        } catch { }
    } elseif ($head -match 'BEGIN ENCRYPTED PRIVATE KEY') {
        $result.Format = 'pkcs8'; $result.State = 'Encrypted'
    } elseif ($head -match 'BEGIN PRIVATE KEY') {
        $result.Format = 'pkcs8'; $result.State = 'Plaintext'
    } elseif ($head -match 'BEGIN [A-Z0-9 ]*PRIVATE KEY') {
        $result.Format = 'pem'
        if ($head -match 'Proc-Type:\s*4,ENCRYPTED' -or $head -match 'DEK-Info') {
            $result.State = 'Encrypted'
            $result.Detail = (($lines | Where-Object { $_ -match 'DEK-Info' }) -join '')
        } else {
            $result.State = 'Plaintext'
        }
    } elseif ($head -match 'PuTTY-User-Key-File') {
        $result.Format = 'ppk'
        $enc = Select-String -LiteralPath $Path -Pattern '^Encryption:\s*(\S+)' | Select-Object -First 1
        if ($enc -and $enc.Matches[0].Groups[1].Value -ieq 'none') {
            $result.State = 'Plaintext'
        } else {
            $result.State = 'Encrypted'
            if ($enc) { $result.Detail = $enc.Matches[0].Value }
        }
    }

    if ($result.State -eq 'Unknown' -and $KeygenPath) {
        $err = & $KeygenPath -y -P '' -f $Path 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            $result.State = 'Plaintext'; $result.Detail = 'ssh-keygen probe'
        } elseif ($err -match 'incorrect passphrase') {
            $result.State = 'Encrypted'; $result.Detail = 'ssh-keygen probe'
        } else {
            $result.Detail = ($err -split "`n")[0]
        }
    }

    return $result
}

function Get-SshKeygenPath {
    $candidates = @(
        (Get-Command ssh-keygen.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe",
        "$env:ProgramFiles\Git\usr\bin\ssh-keygen.exe"
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }
    return $null
}

# ---------------------------------------------------------------------------
# 1. SSH 개인키 passphrase 점검
# ---------------------------------------------------------------------------
Write-Section '1. SSH 개인키 passphrase 점검'

if (-not (Test-Path $SshDir)) {
    Add-Finding INFO 'SSH' "$SshDir 디렉터리가 없음 (Windows 쪽에는 SSH 키 미보관)"
} else {
    Write-Host "  대상 디렉터리: $SshDir"

    $skipNames = @('config', 'known_hosts', 'known_hosts.old', 'authorized_keys', 'agent.env', 'environment')
    $privateKeys = Get-ChildItem -Path $SshDir -File -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Extension -ne '.pub' -and $skipNames -notcontains $_.Name -and $_.Name -notlike '*.bak'
    }

    if (-not $privateKeys) {
        Add-Finding INFO 'SSH' '개인키 파일을 찾지 못함'
    }

    $keygen = Get-SshKeygenPath
    if (-not $keygen) {
        Add-Finding INFO 'SSH' 'ssh-keygen.exe 미발견 — passphrase 판별은 파일 포맷 기반으로 정상 수행되나, 키 지문(fingerprint)은 표시되지 않음'
    }

    foreach ($key in $privateKeys) {
        $head = (Get-Content -LiteralPath $key.FullName -TotalCount 3 -ErrorAction SilentlyContinue) -join "`n"
        if ($head -notmatch 'PRIVATE KEY') {
            continue  # 개인키가 아님
        }

        $info = Get-PrivateKeyEncryptionState -Path $key.FullName -KeygenPath $keygen

        $pub = "$($key.FullName).pub"
        $fingerprint = ''
        if ($keygen -and (Test-Path $pub)) {
            $fingerprint = (& $keygen -l -f $pub 2>$null) -join ' '
        }

        $label = "[" + (@($info.Format, $info.Detail | Where-Object { $_ }) -join ' ') + "]"
        switch ($info.State) {
            'Encrypted' { Add-Finding PASS 'SSH' "$($key.Name) : passphrase 있음 $label $fingerprint" }
            'Plaintext' { Add-Finding FAIL 'SSH' "$($key.Name) : passphrase 없음 — 파일만 유출되면 즉시 사용 가능 $label $fingerprint" }
            default     { Add-Finding WARN 'SSH' "$($key.Name) : passphrase 여부 판별 실패 $label" }
        }
    }

    # ssh config에서 GitHub / GX-10 등에 실제로 쓰이는 키 확인
    $cfg = Join-Path $SshDir 'config'
    if (Test-Path $cfg) {
        Write-Host ''
        Write-Host '  --- ~/.ssh/config 의 Host / IdentityFile 매핑 ---'
        Get-Content $cfg | Where-Object { $_ -match '^\s*(Host|HostName|IdentityFile|User)\s' } | ForEach-Object {
            Write-Host "    $_"
        }
    } else {
        Add-Finding INFO 'SSH' '~/.ssh/config 없음 (기본 키 이름으로 접속 중일 가능성)'
    }

    # 디렉터리 ACL 점검
    Write-Host ''
    Write-Host '  --- .ssh ACL ---'
    $acl = & icacls $SshDir 2>$null
    if (-not $acl) {
        Add-Finding INFO 'SSH' 'icacls 실행 실패 — ACL 을 확인하지 못함'
    } else {
        $acl | ForEach-Object { Write-Host "    $_" }
        if ($acl -match 'BUILTIN\\Users|Everyone|Authenticated Users') {
            Add-Finding WARN 'SSH' '.ssh 에 Users/Everyone 계열 권한이 보임 — 소유자 전용으로 축소 권장'
        } else {
            Add-Finding PASS 'SSH' '.ssh ACL 에 광범위 권한 그룹 없음'
        }
    }

    # ssh-agent 상태
    $agent = Get-Service ssh-agent -ErrorAction SilentlyContinue
    if ($agent) {
        Add-Finding INFO 'SSH' "ssh-agent 서비스: 상태=$($agent.Status), 시작유형=$($agent.StartType)"
        if ($agent.Status -eq 'Running') {
            $loaded = & ssh-add -l 2>&1
            Write-Host '  --- ssh-agent 에 로드된 키 ---'
            $loaded | ForEach-Object { Write-Host "    $_" }
        }
    }
}

# git 자격증명 평문 저장 여부 (SSH 키와 함께 확인할 가치가 있음)
$gitCred = Join-Path $env:USERPROFILE '.git-credentials'
if (Test-Path $gitCred) {
    Add-Finding FAIL 'GIT' '~/.git-credentials 존재 — GitHub 토큰이 평문으로 저장되어 있음'
}
$helper = & git config --global --get credential.helper 2>$null
if ($helper) { Add-Finding INFO 'GIT' "git credential.helper = $helper" }

# ---------------------------------------------------------------------------
# 2. 디스크 암호화 점검
# ---------------------------------------------------------------------------
Write-Section '2. 디스크 암호화(BitLocker / Device Encryption) 점검'

$gotBitlocker = $false
try {
    $vols = Get-BitLockerVolume -ErrorAction Stop
    $gotBitlocker = $true
    foreach ($v in $vols) {
        $msg = "{0} : ProtectionStatus={1}, VolumeStatus={2}, Method={3}, Encrypted={4}%" -f `
            $v.MountPoint, $v.ProtectionStatus, $v.VolumeStatus, $v.EncryptionMethod, $v.EncryptionPercentage
        if ($v.ProtectionStatus -eq 'On') {
            Add-Finding PASS 'DISK' $msg
        } else {
            Add-Finding FAIL 'DISK' $msg
        }
    }
} catch {
    Write-Host '  Get-BitLockerVolume 사용 불가 — WMI/manage-bde 로 재시도' -ForegroundColor DarkGray
}

if (-not $gotBitlocker) {
    try {
        $wmi = Get-CimInstance -Namespace 'root\cimv2\security\microsoftvolumeencryption' `
                               -ClassName Win32_EncryptableVolume -ErrorAction Stop
        foreach ($v in $wmi) {
            $status = switch ($v.ProtectionStatus) { 0 { 'Off' } 1 { 'On' } 2 { 'Unknown' } default { $v.ProtectionStatus } }
            $msg = "$($v.DriveLetter) : ProtectionStatus=$status"
            if ($status -eq 'On') { Add-Finding PASS 'DISK' $msg } else { Add-Finding FAIL 'DISK' $msg }
        }
        $gotBitlocker = $true
    } catch {
        Write-Host '  WMI 조회 실패 (관리자 권한 필요할 수 있음)' -ForegroundColor DarkGray
    }
}

if (-not $gotBitlocker) {
    $mb = & manage-bde -status 2>&1
    $mb | ForEach-Object { Write-Host "    $_" }
    Add-Finding WARN 'DISK' 'BitLocker 상태를 API로 확인하지 못함 — 위 manage-bde 출력을 직접 확인 (관리자 PowerShell 권장)'
}

# Device Encryption(가정용 SKU) 지원 여부
$deInfo = & powercfg /a 2>$null | Out-String
$dePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker'
if (Test-Path $dePath) {
    $de = Get-ItemProperty -Path $dePath -ErrorAction SilentlyContinue
    if ($null -ne $de.PreventDeviceEncryption) {
        Add-Finding INFO 'DISK' "PreventDeviceEncryption = $($de.PreventDeviceEncryption)"
    }
}

# WSL2 가상디스크 위치와 그 드라이브의 암호화 상태 연결
Write-Host ''
Write-Host '  --- WSL2 가상 디스크(ext4.vhdx) 위치 ---'
$wslPkgRoot = Join-Path $env:LOCALAPPDATA 'Packages'
if (Test-Path $wslPkgRoot) {
    $vhdx = Get-ChildItem -Path $wslPkgRoot -Filter 'ext4.vhdx' -Recurse -ErrorAction SilentlyContinue -Depth 4
    if ($vhdx) {
        foreach ($d in $vhdx) {
            $sizeGb = [math]::Round($d.Length / 1GB, 2)
            Write-Host "    $($d.FullName)  (${sizeGb} GB)"
        }
        Add-Finding INFO 'DISK' 'WSL 홈(및 그 안의 ~/.ssh)은 위 vhdx 안에 있으므로, 해당 드라이브의 BitLocker 상태를 그대로 따른다'
    } else {
        Add-Finding INFO 'DISK' 'ext4.vhdx 미발견 (WSL1 이거나 사용자 지정 경로)'
    }
}

# ---------------------------------------------------------------------------
# 3. ~/.ssh 의 백업 / 클라우드 동기화 노출 점검
# ---------------------------------------------------------------------------
Write-Section '3. ~/.ssh 백업 / 클라우드 동기화 노출 점검'

# 3-1. .ssh 가 동기화 루트 하위에 있는지
$syncRoots = @()
foreach ($e in @('OneDrive', 'OneDriveConsumer', 'OneDriveCommercial')) {
    $v = [Environment]::GetEnvironmentVariable($e)
    if ($v) { $syncRoots += [pscustomobject]@{ Name = $e; Path = $v } }
}
$candidatePaths = @(
    @{ Name = 'Dropbox';        Path = Join-Path $env:USERPROFILE 'Dropbox' },
    @{ Name = 'Google Drive';   Path = Join-Path $env:USERPROFILE 'Google Drive' },
    @{ Name = 'My Drive';       Path = 'G:\My Drive' },
    @{ Name = 'iCloudDrive';    Path = Join-Path $env:USERPROFILE 'iCloudDrive' },
    @{ Name = 'Synology Drive'; Path = Join-Path $env:USERPROFILE 'SynologyDrive' },
    @{ Name = 'MEGA';           Path = Join-Path $env:USERPROFILE 'MEGA' },
    @{ Name = 'pCloudDrive';    Path = Join-Path $env:USERPROFILE 'pCloudDrive' },
    @{ Name = 'Nextcloud';      Path = Join-Path $env:USERPROFILE 'Nextcloud' },
    @{ Name = 'Syncthing';      Path = Join-Path $env:USERPROFILE 'Sync' }
)
foreach ($c in $candidatePaths) {
    if (Test-Path $c.Path) { $syncRoots += [pscustomobject]@{ Name = $c.Name; Path = $c.Path } }
}

if ($syncRoots) {
    Write-Host '  탐지된 동기화 루트:'
    $syncRoots | ForEach-Object { Write-Host "    - $($_.Name): $($_.Path)" }
} else {
    Add-Finding PASS 'SYNC' '알려진 클라우드 동기화 클라이언트 폴더가 발견되지 않음'
}

$sshFull = (Resolve-Path $SshDir -ErrorAction SilentlyContinue)
if ($sshFull) {
    $sshFull = $sshFull.Path
    $inside = $false
    foreach ($r in $syncRoots) {
        if ($sshFull.ToLower().StartsWith($r.Path.ToLower())) {
            Add-Finding FAIL 'SYNC' ".ssh 가 동기화 루트 하위에 있음: $($r.Name) ($($r.Path))"
            $inside = $true
        }
    }
    if (-not $inside) {
        Add-Finding PASS 'SYNC' '.ssh 경로 자체는 동기화 루트 하위가 아님'
    }

    # 재분석 지점(심볼릭 링크/정션)으로 우회 동기화되는 경우
    $item = Get-Item -LiteralPath $sshFull -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Add-Finding WARN 'SYNC' ".ssh 가 재분석 지점(링크)임 → 실제 대상: $($item.Target)"
    }
}

# 3-2. 동기화 폴더 안에 키 파일 사본이 흩어져 있는지
if ($syncRoots) {
    Write-Host ''
    Write-Host '  --- 동기화 폴더 내 키 파일 사본 검색 (최대 깊이 5) ---'
    $patterns = @('id_rsa', 'id_ed25519', 'id_ecdsa', '*.pem', '*.ppk', '*.key')
    $hits = @()
    foreach ($r in $syncRoots) {
        foreach ($p in $patterns) {
            $hits += Get-ChildItem -Path $r.Path -Filter $p -Recurse -File -Force -Depth 5 -ErrorAction SilentlyContinue
        }
    }
    $hits = $hits | Sort-Object FullName -Unique
    if ($hits) {
        foreach ($h in $hits) { Add-Finding FAIL 'SYNC' "동기화 폴더에 키로 보이는 파일: $($h.FullName)" }
    } else {
        Add-Finding PASS 'SYNC' '동기화 폴더에서 키 파일 사본을 찾지 못함'
    }
}

# 3-3. OneDrive 알려진 폴더 이동(KFM) 여부
$odAccounts = 'HKCU:\Software\Microsoft\OneDrive\Accounts'
if (Test-Path $odAccounts) {
    Write-Host ''
    Write-Host '  --- OneDrive 계정/폴더 백업(KFM) 설정 ---'
    Get-ChildItem $odAccounts | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        Write-Host "    $($_.PSChildName): UserFolder=$($props.UserFolder)"
    }
    Add-Finding INFO 'SYNC' 'OneDrive 폴더 백업은 보통 바탕화면/문서/사진만 대상 — %USERPROFILE%\.ssh 는 기본 제외이나 설정에서 직접 확인 권장'
}

# 3-4. NAS / 네트워크 드라이브 및 백업 에이전트
Write-Host ''
Write-Host '  --- 매핑된 네트워크 드라이브 (NAS 후보) ---'
$netUse = & net use 2>&1
$netUse | ForEach-Object { Write-Host "    $_" }

Write-Host ''
Write-Host '  --- 백업/동기화 관련 서비스 ---'
$svcPattern = 'backup|veeam|acronis|synology|qnap|cloudstation|duplicati|restic|arq|carbonite|crashplan|idrive|goodsync|resilio|syncthing|nextcloud|dropbox|onedrive|googledrive|drivefs'
$svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $svcPattern -or $_.DisplayName -match $svcPattern }
if ($svcs) {
    $svcs | ForEach-Object { Write-Host "    $($_.Status)`t$($_.Name)`t$($_.DisplayName)" }
    Add-Finding WARN 'BACKUP' '백업/동기화 에이전트가 설치되어 있음 — 해당 제품의 백업 대상에 사용자 프로필(%USERPROFILE%)이 포함되는지 직접 확인 필요'
} else {
    Add-Finding PASS 'BACKUP' '알려진 백업/동기화 서비스가 실행 목록에 없음'
}

Write-Host ''
Write-Host '  --- Windows 파일 기록(File History) ---'
$fh = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory'
if (Test-Path $fh) {
    Get-ItemProperty $fh | Format-List | Out-String | Write-Host
    Add-Finding INFO 'BACKUP' '파일 기록 설정이 존재 — 대상 폴더 목록 확인 권장'
} else {
    Add-Finding PASS 'BACKUP' '파일 기록(File History) 구성 없음'
}

Write-Host ''
Write-Host '  --- .ssh / 사용자 프로필을 참조하는 예약 작업 ---'
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop
    $matched = foreach ($t in $tasks) {
        foreach ($a in $t.Actions) {
            $cmdline = "$($a.Execute) $($a.Arguments)"
            if ($cmdline -match '\.ssh|rclone|restic|robocopy|rsync|duplicati|borg') {
                [pscustomobject]@{ Task = $t.TaskName; Path = $t.TaskPath; Cmd = $cmdline }
            }
        }
    }
    if ($matched) {
        $matched | ForEach-Object { Write-Host "    $($_.Path)$($_.Task) => $($_.Cmd)" }
        Add-Finding WARN 'BACKUP' '.ssh 또는 복사 도구를 호출하는 예약 작업 발견 — 위 목록 확인'
    } else {
        Add-Finding PASS 'BACKUP' '.ssh 를 참조하는 예약 작업 없음'
    }
} catch {
    Add-Finding INFO 'BACKUP' '예약 작업 조회 실패(권한)'
}

# 3-5. rclone / restic 설정 존재 여부 (설정 내용은 출력하지 않음)
$rclone = Join-Path $env:APPDATA 'rclone\rclone.conf'
if (Test-Path $rclone) {
    $remotes = Select-String -Path $rclone -Pattern '^\[(.+)\]$' | ForEach-Object { $_.Matches[0].Groups[1].Value }
    Add-Finding WARN 'BACKUP' "rclone 설정 존재 — remote: $($remotes -join ', ') (동기화 대상 경로 확인 필요)"
}

# ---------------------------------------------------------------------------
# 요약
# ---------------------------------------------------------------------------
Write-Section '요약'
foreach ($lvl in @('FAIL', 'WARN', 'PASS', 'INFO')) {
    $items = $script:Findings | Where-Object { $_.Level -eq $lvl }
    if (-not $items) { continue }
    $color = switch ($lvl) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' } }
    Write-Host ''
    Write-Host "[$lvl] $($items.Count)건" -ForegroundColor $color
    $items | ForEach-Object { Write-Host "  - ($($_.Area)) $($_.Message)" -ForegroundColor $color }
}

Write-Host ''
Write-Host 'WSL 쪽 키는 이 스크립트로 확인되지 않는다. WSL 안에서 check-wsl-security.sh 를 별도로 실행할 것.' -ForegroundColor Cyan
