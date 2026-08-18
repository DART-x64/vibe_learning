#!/usr/bin/env bash
# WSL(Linux) 측 SSH 키 / 디스크 암호화 / 백업·동기화 노출 점검 (읽기 전용)
#
# 사용법:  bash check-wsl-security.sh
#
# 점검 항목
#   1) ~/.ssh 개인키의 passphrase 설정 여부
#   2) WSL 홈이 올라가 있는 저장소의 암호화 상태 (Windows BitLocker 연동 확인)
#   3) ~/.ssh 가 클라우드 동기화 / NAS 백업 경로에 노출되는지
#
# 시스템을 변경하지 않으며 조회만 수행한다.

set -o pipefail

SSH_DIR="${SSH_DIR:-$HOME/.ssh}"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; GRY=$'\033[90m'; RST=$'\033[0m'

FAIL_LIST=(); WARN_LIST=(); PASS_LIST=(); INFO_LIST=(); SYNC_DIRS=()

section() {
    printf '\n%s\n' "${GRY}======================================================================${RST}"
    printf '%s\n'   "${CYN} $1${RST}"
    printf '%s\n'   "${GRY}======================================================================${RST}"
}

finding() {
    local level="$1" area="$2" msg="$3" color
    case "$level" in
        PASS) color=$GRN; PASS_LIST+=("($area) $msg") ;;
        WARN) color=$YEL; WARN_LIST+=("($area) $msg") ;;
        FAIL) color=$RED; FAIL_LIST+=("($area) $msg") ;;
        *)    color=$GRY; INFO_LIST+=("($area) $msg") ;;
    esac
    printf '  %s[%s] %s%s\n' "$color" "$level" "$msg" "$RST"
}

is_wsl() { grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; }

# 개인키 파일의 암호화(=passphrase) 여부를 파일 포맷으로 판별한다.
# 전역 변수 KEY_STATE(encrypted|plaintext|unknown), KEY_FMT, KEY_DETAIL 에 결과를 넣는다.
# ssh-keygen 실행 결과에 의존하지 않으므로 파일 권한 문제로 오판하지 않는다.
detect_key_encryption() {
    local key="$1" first blob
    KEY_STATE="unknown"; KEY_FMT="unknown"; KEY_DETAIL=""

    first="$(head -1 "$key" 2>/dev/null)"
    case "$first" in
        *"BEGIN OPENSSH PRIVATE KEY"*)
            KEY_FMT="openssh"
            # 본문 base64 앞부분: "openssh-key-v1\0" + uint32 + ciphername
            blob="$(sed -e '1d' -e '$d' "$key" 2>/dev/null | tr -d '\r\n' \
                    | base64 -d 2>/dev/null | head -c 64 | tr -c '[:print:]' '.')"
            if printf '%s' "$blob" | grep -q 'openssh-key-v1.*none'; then
                KEY_STATE="plaintext"; KEY_DETAIL="cipher=none"
            elif printf '%s' "$blob" | grep -qE 'openssh-key-v1.*(aes|3des|chacha)'; then
                KEY_STATE="encrypted"
                KEY_DETAIL="cipher=$(printf '%s' "$blob" | grep -oE '(aes[0-9]*-[a-z]+|3des-cbc|chacha20-poly1305[^ ]*)' | head -1)"
            fi
            ;;
        *"BEGIN ENCRYPTED PRIVATE KEY"*)
            KEY_FMT="pkcs8"; KEY_STATE="encrypted" ;;
        *"BEGIN PRIVATE KEY"*)
            KEY_FMT="pkcs8"; KEY_STATE="plaintext" ;;
        *"BEGIN "*"PRIVATE KEY"*)
            KEY_FMT="pem"
            if head -5 "$key" 2>/dev/null | grep -qE 'Proc-Type:[[:space:]]*4,ENCRYPTED|DEK-Info'; then
                KEY_STATE="encrypted"
                KEY_DETAIL="$(head -5 "$key" | grep -i 'DEK-Info' | tr -d '\r')"
            else
                KEY_STATE="plaintext"
            fi
            ;;
        *"PuTTY-User-Key-File"*)
            KEY_FMT="ppk"
            if grep -qiE '^Encryption:[[:space:]]*none' "$key" 2>/dev/null; then
                KEY_STATE="plaintext"
            else
                KEY_STATE="encrypted"
                KEY_DETAIL="$(grep -i '^Encryption:' "$key" | head -1 | tr -d '\r')"
            fi
            ;;
    esac

    # 포맷으로 판별이 안 된 경우에만 ssh-keygen 으로 보조 확인.
    # exit=0 이면 passphrase 없음, stderr 에 incorrect passphrase 가 있으면 있음.
    if [ "$KEY_STATE" = "unknown" ] && command -v ssh-keygen >/dev/null 2>&1; then
        local err rc
        err="$(ssh-keygen -y -P '' -f "$key" 2>&1 >/dev/null)"; rc=$?
        if [ "$rc" -eq 0 ]; then
            KEY_STATE="plaintext"; KEY_DETAIL="ssh-keygen probe"
        elif printf '%s' "$err" | grep -qi 'incorrect passphrase'; then
            KEY_STATE="encrypted"; KEY_DETAIL="ssh-keygen probe"
        else
            KEY_DETAIL="$(printf '%s' "$err" | head -1)"
        fi
    fi
}

# Windows 사용자 프로필 경로 추정 (interop 사용 가능 시)
win_userprofile() {
    command -v cmd.exe >/dev/null 2>&1 || return 1
    cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r' | head -1
}

# ---------------------------------------------------------------------------
section "0. 환경 정보"
# ---------------------------------------------------------------------------
printf '  호스트  : %s\n' "$(hostname)"
printf '  커널    : %s\n' "$(uname -r)"
if is_wsl; then
    printf '  환경    : WSL (%s)\n' "${WSL_DISTRO_NAME:-distro unknown}"
    if [ -n "${WSL_INTEROP:-}" ] || command -v cmd.exe >/dev/null 2>&1; then
        printf '  interop : 사용 가능 (Windows 명령 호출 가능)\n'
    else
        printf '  interop : 사용 불가 — Windows 측 항목은 PowerShell 스크립트로 별도 확인 필요\n'
    fi
else
    printf '  환경    : WSL 아님 (일반 Linux)\n'
fi
printf '  홈      : %s (%s)\n' "$HOME" "$(df -h "$HOME" 2>/dev/null | awk 'NR==2{print $1" on "$6}')"

# ---------------------------------------------------------------------------
section "1. SSH 개인키 passphrase 점검"
# ---------------------------------------------------------------------------
if [ ! -d "$SSH_DIR" ]; then
    finding INFO SSH "$SSH_DIR 없음 — WSL 안에는 SSH 키가 없음"
else
    echo "  대상 디렉터리: $SSH_DIR"
    found_key=0
    while IFS= read -r -d '' key; do
        base="$(basename "$key")"
        case "$base" in
            *.pub|config|known_hosts|known_hosts.old|authorized_keys|environment|agent.env) continue ;;
        esac
        head -1 "$key" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
        found_key=1

        # 권한 점검 (판별보다 먼저 — 권한이 느슨하면 그 자체로 노출 위험)
        perm="$(stat -c '%a' "$key" 2>/dev/null)"
        if [ -n "$perm" ] && [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
            finding WARN SSH "$base : 파일 권한 $perm — 소유자 외 읽기 가능 (600 권장)"
        fi

        fp=""
        [ -f "$key.pub" ] && fp="$(ssh-keygen -l -f "$key.pub" 2>/dev/null)"

        detect_key_encryption "$key"
        case "$KEY_STATE" in
            encrypted)
                finding PASS SSH "$base : passphrase 있음 [$KEY_FMT ${KEY_DETAIL}] $fp" ;;
            plaintext)
                finding FAIL SSH "$base : passphrase 없음 — 파일만 유출되면 즉시 사용 가능 [$KEY_FMT] $fp" ;;
            *)
                finding WARN SSH "$base : passphrase 여부 판별 실패 [$KEY_FMT] ${KEY_DETAIL}" ;;
        esac
    done < <(find "$SSH_DIR" -maxdepth 1 -type f -print0 2>/dev/null)

    [ "$found_key" -eq 0 ] && finding INFO SSH "개인키 파일을 찾지 못함"

    dperm="$(stat -c '%a' "$SSH_DIR" 2>/dev/null)"
    if [ "$dperm" = "700" ]; then
        finding PASS SSH ".ssh 디렉터리 권한 700"
    else
        finding WARN SSH ".ssh 디렉터리 권한 $dperm (700 권장)"
    fi

    if [ -f "$SSH_DIR/config" ]; then
        echo ""
        echo "  --- ~/.ssh/config 의 Host / IdentityFile 매핑 ---"
        grep -iE '^[[:space:]]*(Host|HostName|IdentityFile|User)[[:space:]]' "$SSH_DIR/config" | sed 's/^/    /'
    else
        finding INFO SSH "~/.ssh/config 없음"
    fi

    if [ -n "${SSH_AUTH_SOCK:-}" ]; then
        echo ""
        echo "  --- ssh-agent 에 로드된 키 ---"
        ssh-add -l 2>&1 | sed 's/^/    /'
    else
        finding INFO SSH "SSH_AUTH_SOCK 미설정 — 현재 셸에 ssh-agent 없음"
    fi
fi

# git 자격증명 평문 저장
if [ -f "$HOME/.git-credentials" ]; then
    finding FAIL GIT "~/.git-credentials 존재 — GitHub 토큰이 평문으로 저장되어 있음"
fi
helper="$(git config --global --get credential.helper 2>/dev/null)"
[ -n "$helper" ] && finding INFO GIT "git credential.helper = $helper"
if [ -f "$HOME/.config/gh/hosts.yml" ] && grep -q 'oauth_token' "$HOME/.config/gh/hosts.yml" 2>/dev/null; then
    finding WARN GIT "~/.config/gh/hosts.yml 에 gh 토큰이 평문 저장되어 있음"
fi

# ---------------------------------------------------------------------------
section "2. 디스크 암호화 점검"
# ---------------------------------------------------------------------------
# WSL2 홈은 ext4.vhdx 안에 있고, 그 파일은 Windows 볼륨 위에 있다.
# 따라서 실질적인 저장 시 암호화 = 해당 Windows 볼륨의 BitLocker 상태.
if is_wsl; then
    echo "  WSL 홈은 ext4.vhdx(가상 디스크) 안에 있으며, 저장 시 암호화 여부는"
    echo "  그 vhdx 가 놓인 Windows 볼륨의 BitLocker 상태를 그대로 따른다."
    echo ""
    if command -v powershell.exe >/dev/null 2>&1; then
        echo "  --- Windows BitLocker 상태 (interop 조회) ---"
        bl="$(powershell.exe -NoProfile -NonInteractive -Command \
            "try { Get-BitLockerVolume | ForEach-Object { \$_.MountPoint + ' ProtectionStatus=' + \$_.ProtectionStatus + ' VolumeStatus=' + \$_.VolumeStatus } } catch { 'QUERY_FAILED' }" 2>/dev/null | tr -d '\r')"
        if [ -z "$bl" ] || echo "$bl" | grep -q 'QUERY_FAILED'; then
            finding WARN DISK "BitLocker 상태 조회 실패 — 관리자 PowerShell 에서 'manage-bde -status' 로 직접 확인"
        else
            echo "$bl" | sed 's/^/    /'
            if echo "$bl" | grep -q 'ProtectionStatus=On'; then
                finding PASS DISK "BitLocker 보호가 켜진 볼륨이 있음 (위 목록에서 C: 포함 여부 확인)"
            fi
            if echo "$bl" | grep -q 'ProtectionStatus=Off'; then
                finding FAIL DISK "BitLocker 가 꺼진 볼륨이 있음 — 해당 볼륨의 데이터는 평문 저장"
            fi
        fi
    else
        finding WARN DISK "interop 불가 — Windows 측에서 Check-WorkstationSecurity.ps1 실행 필요"
    fi
else
    echo "  --- 블록 장치 / 암호화 계층 ---"
    lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT 2>/dev/null | sed 's/^/    /'
    if lsblk -o FSTYPE 2>/dev/null | grep -qi 'crypto_LUKS'; then
        finding PASS DISK "LUKS 암호화 볼륨 탐지됨"
    else
        finding WARN DISK "LUKS 암호화 볼륨을 찾지 못함 — 전체 디스크 암호화 미적용 가능성"
    fi
fi

# ---------------------------------------------------------------------------
section "3. ~/.ssh 백업 / 클라우드 동기화 노출 점검"
# ---------------------------------------------------------------------------

# 3-1. ~/.ssh 가 Windows 파일시스템(/mnt/c 등)에 심볼릭 링크되어 있는지
if [ -L "$SSH_DIR" ]; then
    target="$(readlink -f "$SSH_DIR")"
    finding WARN SYNC ".ssh 가 심볼릭 링크임 → 실제 위치: $target"
    case "$target" in
        /mnt/*) finding FAIL SYNC ".ssh 실체가 Windows 파일시스템에 있음 — Windows 측 백업/동기화 대상에 포함될 수 있음" ;;
    esac
else
    finding PASS SYNC ".ssh 는 WSL 내부 경로의 실제 디렉터리 (심볼릭 링크 아님)"
fi

# 홈 자체가 /mnt 아래인지
case "$(readlink -f "$HOME")" in
    /mnt/*) finding FAIL SYNC "홈 디렉터리가 $HOME → Windows 파일시스템 위에 있음 (백업/동기화 노출 가능)" ;;
    *)      finding PASS SYNC "홈 디렉터리가 WSL 내부 파일시스템에 있음" ;;
esac

# 3-2. Windows 사용자 프로필 하위의 동기화 폴더 및 키 사본 검색
if is_wsl && command -v cmd.exe >/dev/null 2>&1; then
    wprofile_win="$(win_userprofile)"
    if [ -n "$wprofile_win" ]; then
        # C:\Users\foo -> /mnt/c/Users/foo
        drive="$(printf '%s' "$wprofile_win" | cut -c1 | tr 'A-Z' 'a-z')"
        rest="$(printf '%s' "$wprofile_win" | cut -c3- | tr '\\' '/')"
        WPROFILE="/mnt/$drive$rest"
    fi
fi
: "${WPROFILE:=/mnt/c/Users/$USER}"

if [ -d "$WPROFILE" ]; then
    echo ""
    echo "  Windows 프로필 경로: $WPROFILE"
    echo "  --- 탐지된 클라우드 동기화 폴더 ---"
    sync_found=0
    while IFS= read -r d; do
        [ -z "$d" ] && continue
        echo "    - $d"
        sync_found=1
        SYNC_DIRS+=("$d")
    done < <(find "$WPROFILE" -maxdepth 1 -mindepth 1 -type d \
                  \( -iname 'OneDrive*' -o -iname 'Dropbox' -o -iname 'Google*Drive' \
                     -o -iname 'iCloudDrive' -o -iname 'SynologyDrive' -o -iname 'Nextcloud' \
                     -o -iname 'MEGA' -o -iname 'pCloudDrive' -o -iname 'Sync' \) 2>/dev/null)
    [ "$sync_found" -eq 0 ] && finding PASS SYNC "Windows 프로필에서 알려진 동기화 폴더를 찾지 못함"

    # Windows 측 .ssh 도 함께 확인
    if [ -d "$WPROFILE/.ssh" ]; then
        wkeys="$(find "$WPROFILE/.ssh" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | wc -l)"
        finding INFO SYNC "Windows 측 $WPROFILE/.ssh 존재 (파일 $wkeys 개) — PowerShell 스크립트로 passphrase 별도 점검 필요"
    fi

    # 동기화 폴더 안의 키 사본 검색
    if [ "${#SYNC_DIRS[@]}" -gt 0 ]; then
        echo ""
        echo "  --- 동기화 폴더 내 키 파일 사본 검색 (최대 깊이 5) ---"
        hits="$(find "${SYNC_DIRS[@]}" -maxdepth 5 -type f \
                 \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \
                    -o -name '*.pem' -o -name '*.ppk' -o -name '*.key' \) 2>/dev/null)"
        if [ -n "$hits" ]; then
            echo "$hits" | sed 's/^/    /'
            finding FAIL SYNC "동기화 폴더에서 키로 보이는 파일 발견 (위 목록) — 즉시 제거/회수 검토"
        else
            finding PASS SYNC "동기화 폴더에서 키 파일 사본을 찾지 못함"
        fi
    fi
fi

# 3-3. Linux 측 백업 도구 / 스케줄
echo ""
echo "  --- 설치된 백업·동기화 도구 ---"
tools_found=0
for t in rclone restic borg borgmatic duplicity duplicati rsync syncthing; do
    if command -v "$t" >/dev/null 2>&1; then
        printf '    - %s (%s)\n' "$t" "$(command -v "$t")"
        tools_found=1
    fi
done
[ "$tools_found" -eq 0 ] && echo "    (없음)"

# rclone remote 이름만 출력 (자격증명은 출력하지 않음)
if [ -f "$HOME/.config/rclone/rclone.conf" ]; then
    remotes="$(grep -oE '^\[.*\]$' "$HOME/.config/rclone/rclone.conf" | tr -d '[]' | paste -sd', ')"
    finding WARN BACKUP "rclone 설정 존재 — remote: $remotes (동기화 대상 경로 확인 필요)"
fi
for f in "$HOME/.config/borgmatic/config.yaml" "/etc/borgmatic/config.yaml" "$HOME/.restic-env" "$HOME/.duplicati"; do
    [ -e "$f" ] && finding WARN BACKUP "백업 설정 파일 존재: $f — 백업 대상에 \$HOME 포함 여부 확인"
done

echo ""
echo "  --- cron / systemd timer 에서 백업·복사 관련 항목 ---"
cron_hits="$( { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } \
    | grep -vE '^\s*#' | grep -EI 'rsync|rclone|restic|borg|duplicati|tar|\.ssh' )"
if [ -n "$cron_hits" ]; then
    echo "$cron_hits" | sed 's/^/    /'
    finding WARN BACKUP "cron 에 백업/복사 작업이 있음 — 대상 경로에 ~/.ssh 포함 여부 확인"
else
    echo "    (해당 없음)"
    finding PASS BACKUP "cron 에 ~/.ssh 를 다루는 백업 작업 없음"
fi

if command -v systemctl >/dev/null 2>&1; then
    timers="$(systemctl list-timers --all --no-pager 2>/dev/null | grep -EI 'backup|rsync|restic|borg|rclone')"
    if [ -n "$timers" ]; then
        echo "$timers" | sed 's/^/    /'
        finding WARN BACKUP "백업 관련 systemd timer 발견"
    fi
fi

echo ""
echo "  --- 마운트된 NAS / 네트워크 파일시스템 ---"
netmounts="$(mount 2>/dev/null | grep -EI 'type (nfs|nfs4|cifs|smb|smbfs|sshfs|fuse\.sshfs)')"
if [ -n "$netmounts" ]; then
    echo "$netmounts" | sed 's/^/    /'
    finding WARN BACKUP "네트워크 파일시스템이 마운트되어 있음 — NAS 백업 잡의 대상 경로 확인 필요"
else
    echo "    (없음)"
    finding PASS BACKUP "마운트된 NAS/네트워크 파일시스템 없음"
fi

# 3-4. 리포지토리에 키가 커밋되지 않았는지 (현재 디렉터리가 git repo 인 경우)
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked="$(git ls-files | grep -EI '(^|/)(id_rsa|id_ed25519|id_ecdsa)$|\.pem$|\.ppk$|(^|/)\.ssh/' || true)"
    if [ -n "$tracked" ]; then
        echo "$tracked" | sed 's/^/    /'
        finding FAIL GIT "현재 git 저장소에 키로 보이는 파일이 추적되고 있음"
    else
        finding PASS GIT "현재 git 저장소에 추적 중인 키 파일 없음"
    fi
fi

# ---------------------------------------------------------------------------
section "요약"
# ---------------------------------------------------------------------------
print_list() {
    local label="$1" color="$2"; shift 2
    [ "$#" -eq 0 ] && return
    printf '\n%s[%s] %d건%s\n' "$color" "$label" "$#" "$RST"
    for i in "$@"; do printf '%s  - %s%s\n' "$color" "$i" "$RST"; done
}
print_list FAIL "$RED"  "${FAIL_LIST[@]}"
print_list WARN "$YEL"  "${WARN_LIST[@]}"
print_list PASS "$GRN"  "${PASS_LIST[@]}"
print_list INFO "$GRY"  "${INFO_LIST[@]}"

printf '\n%sWindows 측(사용자 프로필의 .ssh, BitLocker, 백업 에이전트)은 PowerShell 에서%s\n' "$CYN" "$RST"
printf '%sCheck-WorkstationSecurity.ps1 을 실행해 함께 확인할 것.%s\n' "$CYN" "$RST"

[ "${#FAIL_LIST[@]}" -gt 0 ] && exit 1
exit 0
