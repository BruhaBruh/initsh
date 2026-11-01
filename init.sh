#!/bin/bash
# Первичная настройка VPS (Debian/Ubuntu). Запускать ЛОКАЛЬНО:
#   ./init.sh <ip> [ssh-порт]
#   curl -fsSL https://raw.githubusercontent.com/BruhaBruh/initsh/main/init.sh | bash -s -- <ip> [ssh-порт]
# Скрипт сам зайдёт на сервер под root, создаст пользователя, положит твой
# публичный ключ, проверит вход по ключу и только потом закроет root и пароли.
# Повторный запуск безопасен (идемпотентно), пока root ещё пускают.
#
# Переменные окружения:
#   INIT_USER    имя пользователя        (по умолчанию bruhabruh)
#   PUBKEY_FILE  публичный ключ          (по умолчанию ~/.ssh/id_rsa.pub)

set -euo pipefail

USERNAME="${INIT_USER:-bruhabruh}"
PUBKEY_FILE="${PUBKEY_FILE:-$HOME/.ssh/id_rsa.pub}"
UFW_ALLOW=(22/tcp 80/tcp 443/tcp)

log() { echo "[init $(date '+%F %T')] $*"; }
die() { echo "ОШИБКА: $*" >&2; exit 1; }

# ============================================================================
#  REMOTE: эти функции выполняются на сервере под root
# ============================================================================

remote_phase1() {   # $1 = хеш пароля, $2 = публичный ключ
    local pass_hash=$1 pubkey=$2
    [[ $EUID -eq 0 ]] || die "нужен root"
    command -v apt-get >/dev/null || die "нужен Debian/Ubuntu"
    export DEBIAN_FRONTEND=noninteractive

    log "Ставлю пакеты"
    local apt=(apt-get -o DPkg::Lock::Timeout=300 -y)
    "${apt[@]}" update
    "${apt[@]}" install sudo openssh-server fail2ban python3-systemd ufw unattended-upgrades

    log "Пользователь $USERNAME"
    id "$USERNAME" &>/dev/null || useradd -m -s /bin/bash "$USERNAME"
    usermod -aG sudo "$USERNAME"
    usermod -p "$pass_hash" "$USERNAME"
    rm -f "/etc/sudoers.d/90-$USERNAME"   # остаток старой NOPASSWD-версии, если был

    log "SSH-ключ"
    local home ssh_dir
    home=$(getent passwd "$USERNAME" | cut -d: -f6)
    ssh_dir="$home/.ssh"
    install -d -m 700 -o "$USERNAME" -g "$USERNAME" "$ssh_dir"
    touch "$ssh_dir/authorized_keys"
    grep -qxF "$pubkey" "$ssh_dir/authorized_keys" || echo "$pubkey" >> "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/authorized_keys"
    chown "$USERNAME:$USERNAME" "$ssh_dir/authorized_keys"

    log "fail2ban"
    local my_ip=${SSH_CLIENT%% *}
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# IP, с которого запускали init.sh, не банится никогда
ignoreip = 127.0.0.1/8 ::1 ${my_ip}
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
# на Debian 12+ нет /var/log/auth.log, читаем journald
backend = systemd
EOF
    systemctl enable fail2ban
    systemctl restart fail2ban
    log "fail2ban: в белом списке ${my_ip}"

    log "ufw"
    ufw default deny incoming
    ufw default allow outgoing
    local rule
    for rule in "${UFW_ALLOW[@]}"; do ufw allow "$rule"; done
    ufw --force enable

    log "unattended-upgrades"
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    systemctl enable unattended-upgrades
}

remote_phase2() {   # закрываем root и пароли
    [[ $EUID -eq 0 ]] || die "нужен root"
    log "sshd: запрещаю root и пароли"
    local main=/etc/ssh/sshd_config
    mkdir -p /etc/ssh/sshd_config.d /run/sshd

    # в sshd побеждает первое значение; без Include дроп-ины не читаются
    grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$main" \
        || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$main"

    # 00- грузится раньше 50-cloud-init.conf с его PasswordAuthentication yes
    cat > /etc/ssh/sshd_config.d/00-hardening.conf <<EOF
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AllowUsers $USERNAME
EOF
    sshd -t

    local eff want
    eff=$(sshd -T -C user="$USERNAME",host=localhost,addr=127.0.0.1)
    for want in "permitrootlogin no" "passwordauthentication no" "pubkeyauthentication yes"; do
        grep -qx "$want" <<<"$eff" || die "sshd -T: нет '$want'"
    done

    systemctl restart ssh 2>/dev/null || systemctl restart sshd
}

# ============================================================================
#  LOCAL
# ============================================================================

# Код для сервера собирается из живых функций, а не из файла:
# так работает и ./init.sh, и bash <(curl ...), и curl | bash.
remote_payload() {   # $1 = какую функцию вызвать на сервере
    echo 'set -euo pipefail'
    declare -p USERNAME UFW_ALLOW
    declare -f log die remote_phase1 remote_phase2
    # stdin на сервере — сам скрипт; apt и прочие не должны его читать
    echo "$1 \"\$@\" </dev/null"
}

main() {
    local host=${1:-} port=${2:-22}
    [[ -n $host ]] || die "использование: init.sh <ip> [ssh-порт]"
    [[ $USERNAME =~ ^[a-z_][a-z0-9_-]*$ ]] || die "плохое имя пользователя: $USERNAME"
    [[ -r $PUBKEY_FILE ]] || die "нет ключа $PUBKEY_FILE"
    command -v openssl >/dev/null || die "нужен openssl"
    ssh-keygen -lf "$PUBKEY_FILE" >/dev/null || die "$PUBKEY_FILE невалиден"

    local pubkey pass pass2 generated=0 pass_hash
    pubkey=$(<"$PUBKEY_FILE")

    # из /dev/tty: при запуске через curl | bash stdin занят самим скриптом
    read -rsp "Пароль для $USERNAME (Enter — сгенерировать): " pass </dev/tty; echo
    if [[ -z $pass ]]; then
        pass=$(openssl rand -base64 18)
        generated=1
    else
        read -rsp "Повтори: " pass2 </dev/tty; echo
        [[ $pass == "$pass2" ]] || die "пароли не совпали"
    fi
    pass_hash=$(openssl passwd -6 -stdin <<<"$pass")

    # одно соединение под root на обе фазы: пароль root спросят максимум раз
    local ctl
    ctl=$(mktemp -d)
    # значения подставляются сразу: на EXIT локальных переменных main уже нет
    # shellcheck disable=SC2064
    trap "ssh -o ControlPath=$(printf %q "$ctl/root") -O exit $(printf %q "root@$host") 2>/dev/null; rm -rf $(printf %q "$ctl")" EXIT
    local ssh_opts=(-p "$port" -o StrictHostKeyChecking=accept-new)
    local root_ssh=(ssh "${ssh_opts[@]}" -o ControlMaster=auto -o ControlPath="$ctl/root" -o ControlPersist=120 "root@$host")
    local user_ssh=(ssh -n "${ssh_opts[@]}" -o ControlPath=none -o BatchMode=yes -o IdentitiesOnly=yes -i "${PUBKEY_FILE%.pub}" "$USERNAME@$host")

    log "Фаза 1 на $host"
    "${root_ssh[@]}" "bash -s -- $(printf %q "$pass_hash") $(printf %q "$pubkey")" < <(remote_payload remote_phase1)

    log "Проверяю вход $USERNAME по ключу"
    "${user_ssh[@]}" 'id -nG | grep -qw sudo' \
        || die "$USERNAME не входит по ключу — root НЕ закрыт, разбирайся"

    log "Фаза 2 на $host"
    "${root_ssh[@]}" "bash -s" < <(remote_payload remote_phase2)

    log "Финальная проверка"
    # при провале не закрываем root-сессию: через неё можно откатить конфиг
    "${user_ssh[@]}" true || { trap - EXIT; die "после фазы 2 $USERNAME не входит! Открытая root-сессия ещё жива 120 сек: ssh -o ControlPath=$ctl/root root@$host"; }
    if ssh -n "${ssh_opts[@]}" -o ControlPath=none -o BatchMode=yes "root@$host" true 2>/dev/null; then
        die "root всё ещё пускают"
    fi

    echo
    log "Готово: ssh -p $port $USERNAME@$host"
    if (( generated )); then
        echo "Пароль $USERNAME (для sudo), сохрани:  $pass"
    fi
}

main "$@"
