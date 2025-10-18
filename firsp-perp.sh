#!/usr/bin/env bash
# VPS Initial Setup Script
# Поддерживаемые ОС: Ubuntu, Debian
# Интерактивный комбинированный режим
# Резервные копии конфигов в /root/vps-setup-backup/
# Итоговый отчет выводится в консоль

set -e

# Цветовая схема
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; BLUE="\e[34m"; RESET="\e[0m"

# Функции
backup_file() {
    src="$1"
    dst="/root/vps-setup-backup${src}"
    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"
    echo -e "${YELLOW}Backed up $src -> $dst${RESET}"
}

log_action() {
    actions+=("$1")
    echo -e "${BLUE}* $1${RESET}"
}

declare -a actions

#### 1) Обновление системы ####
echo -e "${GREEN}== Шаг 1: Обновление системы ==${RESET}"
apt update && apt upgrade -y
apt autoremove -y && apt autoclean -y
echo -e "${YELLOW}Если требуется перезагрузка, выберите:${RESET}"
select opt in "Перезагрузить сейчас" "Перезагрузить позже" "Не перезагружать"; do
    case $opt in
        "Перезагрузить сейчас") reboot;;
        "Перезагрузить позже") log_action "Обновление выполнено, перезагрузка отложена"; break;;
        "Не перезагружать") log_action "Обновление выполнено без перезагрузки"; break;;
    esac
done

#### 2) Изменение hostname ####
echo -e "${GREEN}== Шаг 2: Настройка hostname ==${RESET}"
current=$(hostname)
echo "Текущее имя хоста: $current"
default_hn="vps-$(date +%Y%m%d)"
read -rp "Введите имя хоста [${default_hn}]: " hn
hn=${hn:-$default_hn}
if [[ ! $hn =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
    echo -e "${RED}Ошибка: Некорректный формат hostname${RESET}"
    exit 1
fi
backup_file /etc/hostname
echo "$hn" > /etc/hostname
hostnamectl set-hostname "$hn"
backup_file /etc/hosts
sed -i "/127.0.1.1/d" /etc/hosts
echo "127.0.1.1    $hn" >> /etc/hosts
log_action "Hostname изменён на $hn"

#### 3) Создание пользователя с sudo ####
echo -e "${GREEN}== Шаг 3: Пользователь с sudo ==${RESET}"
if [[ $EUID -ne 0 ]]; then
    must_create=1
else
    must_create=0
fi
if (( must_create )); then
    create_user="y"
else
    read -rp "Создать нового пользователя? [y/N]: " create_user
fi
if [[ $create_user =~ ^[Yy] ]]; then
    read -rp "Введите имя пользователя: " usr
    read -rsp "Введите пароль для $usr: " pwd; echo
    useradd -m -s /bin/bash "$usr"
    echo "$usr:$pwd" | chpasswd
    usermod -aG sudo "$usr"
    if [[ -f /root/.ssh/authorized_keys ]]; then
        mkdir -p /home/"$usr"/.ssh
        cp /root/.ssh/authorized_keys /home/"$usr"/.ssh/
        chown -R "$usr":"$usr" /home/"$usr"/.ssh
        chmod 700 /home/"$usr"/.ssh
        chmod 600 /home/"$usr"/.ssh/authorized_keys
        log_action "Ключи SSH скопированы для $usr"
    fi
    su - "$usr" -c "sudo -n true" && log_action "Пользователь $usr имеет sudo"
fi

#### 4) Настройка SSH ####
echo -e "${GREEN}== Шаг 4: SSH Configuration ==${RESET}"
SSH_CONF=/etc/ssh/sshd_config
backup_file "$SSH_CONF"
rnd_port=$((RANDOM%(65535-1024)+1024))
read -rp "Введите порт SSH [${rnd_port}]: " ssh_port
ssh_port=${ssh_port:-$rnd_port}
cat > "$SSH_CONF" << EOF
Port $ssh_port
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
systemctl reload sshd
log_action "SSH настроен на порт $ssh_port, доступ по ключам"

#### 5) Настройка UFW ####
echo -e "${GREEN}== Шаг 5: Настройка UFW ==${RESET}"
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow "$ssh_port"/tcp
log_action "UFW: открыт порт SSH $ssh_port"
ufw --force enable
log_action "UFW включён"

#### 6) Настройка Fail2ban ####
echo -e "${GREEN}== Шаг 6: Fail2ban ==${RESET}"
apt install -y fail2ban
JAIL=/etc/fail2ban/jail.local
backup_file "$JAIL"
cat > "$JAIL" << EOF
[DEFAULT]
bantime = 10800
findtime = 36000
maxretry = 4
banaction = iptables-multiport
bantime.increment = 1800
bantime.max = 864000

[sshd]
enabled = true
port = $ssh_port
logpath = /var/log/auth.log
EOF
systemctl enable --now fail2ban
log_action "Fail2ban активирован (maxretry=4, bantime 3ч→10д, findtime=10ч)"

#### 7) Настройка SWAP ####
echo -e "${GREEN}== Шаг 7: Swap ==${RESET}"
swapfile=/swapfile
if ! swapon --show | grep -q "$swapfile"; then
    fallocate -l 2G "$swapfile"
    chmod 600 "$swapfile"
    mkswap "$swapfile"
    swapon "$swapfile"
    echo "$swapfile none swap sw 0 0" >> /etc/fstab
    sysctl vm.swappiness=10
    sysctl vm.vfs_cache_pressure=50
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    log_action "Создан и включен SWAP 2G (swappiness=10, cache_pressure=50)"
fi

#### 8) Настройка sysctl ####
echo -e "${GREEN}== Шаг 8: Sysctl tuning ==${RESET}"
backup_file /etc/sysctl.conf
cat >> /etc/sysctl.conf << EOF
# Сетевая безопасность
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.tcp_syncookies = 1

# Производительность сети
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 87380 16777216
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_fastopen = 3

# Память
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# Файлы
fs.file-max = 200000
EOF
sysctl -p
log_action "Параметры ядра применены"

#### 9) Настройка Logrotate ####
echo -e "${GREEN}== Шаг 9: Logrotate ==${RESET}"
cat > /etc/logrotate.d/custom << EOF
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
log_action "Logrotate для основных логов настроен"

#### Итоговый отчёт ####
echo -e "${GREEN}== Итоговое резюме шагов ==${RESET}"
for i in "${!actions[@]}"; do
    printf "%2d. %s\n" $((i+1)) "${actions[i]}"
done
echo -e "${GREEN}== Скрипт завершён ==${RESET}"
