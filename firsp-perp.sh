#!/usr/bin/env bash
# VPS Initial Setup Script
# Поддерживаемые ОС: Ubuntu, Debian
# Интерактивный комбинированный режим
# Резервные копии конфигов в /root/vps-setup-backup/
# Итоговый отчёт выводится в консоль

set -e

# Цветовая схема
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; BLUE="\e[34m"; RESET="\e[0m"

# Массив для итогового отчёта
declare -a actions

backup_file() {
    src="$1"
    dst="/root/vps-setup-backup${src}"
    mkdir -p "$(dirname "$dst")"
    cp -p "$src" "$dst"
    echo -e "${YELLOW}Backed up $src → $dst${RESET}"
}

log_action() {
    actions+=("$1")
    echo -e "${BLUE}* $1${RESET}"
}

handle_error() {
    echo -e "${RED}Ошибка на шаге: $1${RESET}"
    select opt in "Прервать выполнение" "Пропустить шаг"; do
        case $opt in
            "Прервать выполнение") echo -e "${RED}Скрипт прерван${RESET}"; exit 1;;
            "Пропустить шаг") log_action "Шаг пропущен: $1"; return;;
        esac
    done
}

run_step() {
    description="$1"; shift
    if ! "$@"; then
        handle_error "$description"
    else
        log_action "$description выполнен"
    fi
}

# Определяем SSH-сервис
SSH_SERVICE=$(systemctl list-unit-files | grep -E 'ssh.service|sshd.service' | head -n1 | awk '{print $1}')

# Список шагов
steps=(
    "1) Обновление системы"
    "2) Изменение hostname"
    "3) Создание пользователя с sudo"
    "4) Настройка SSH"
    "5) Настройка UFW"
    "6) Настройка Fail2ban"
    "7) Настройка SWAP"
    "8) Настройка sysctl"
    "9) Настройка Logrotate"
)

# Выбор шагов
echo -e "${GREEN}Выберите шаг для выполнения или 'all' для всех:${RESET}"
for s in "${steps[@]}"; do echo "$s"; done
echo "all) Выполнить всё"
read -rp "Введите номер шага или all: " choice

run_all=false
if [[ $choice == "all" ]]; then run_all=true; fi

# Функции-реализации шагов
step1() {
    echo -e "${GREEN}== Шаг 1: Обновление системы ==${RESET}"
    run_step "apt update && apt upgrade" bash -c "apt update && apt upgrade -y"
    run_step "Очистка пакетов" bash -c "apt autoremove -y && apt autoclean -y"
    echo -e "${YELLOW}Если требуется перезагрузка, выберите:${RESET}"
    select opt in "Перезагрузить сейчас" "Перезагрузить позже" "Не перезагружать"; do
        case $opt in
            "Перезагрузить сейчас") reboot;;
            "Перезагрузить позже") log_action "Обновление выполнено, перезагрузка отложена"; break;;
            "Не перезагружать") log_action "Обновление выполнено без перезагрузки"; break;;
        esac
    done
}

step2() {
    echo -e "${GREEN}== Шаг 2: Настройка hostname ==${RESET}"
    current=$(hostname); echo "Текущее имя хоста: $current"
    default_hn="vps-$(date +%Y%m%d)"
    read -rp "Введите имя хоста [${default_hn}]: " hn; hn=${hn:-$default_hn}
    if [[ ! $hn =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
        echo -e "${RED}Некорректный формат hostname${RESET}"; exit 1
    fi
    run_step "Backup /etc/hostname" backup_file /etc/hostname
    run_step "Установка hostname" bash -c "echo \"$hn\" > /etc/hostname && hostnamectl set-hostname \"$hn\""
    run_step "Backup /etc/hosts" backup_file /etc/hosts
    run_step "Обновление /etc/hosts" bash -c "sed -i '/127.0.1.1/d' /etc/hosts && echo '127.0.1.1    $hn' >> /etc/hosts"
}

step3() {
    echo -e "${GREEN}== Шаг 3: Пользователь с sudo ==${RESET}"
    if [[ $EUID -ne 0 ]]; then must_create=1; else must_create=0; fi
    if (( must_create )); then create_user="y"; else read -rp "Создать нового пользователя? [y/N]: " create_user; fi
    if [[ $create_user =~ ^[Yy] ]]; then
        read -rp "Введите имя пользователя: " usr
        read -rsp "Введите пароль для $usr: " pwd; echo
        run_step "Создание пользователя $usr" useradd -m -s /bin/bash "$usr"
        run_step "Установка пароля для $usr" bash -c "echo \"$usr:$pwd\" | chpasswd"
        run_step "Добавление $usr в sudo" usermod -aG sudo "$usr"
        if [[ -f /root/.ssh/authorized_keys ]]; then
            run_step "Копирование SSH-ключей для $usr" bash -c "mkdir -p /home/$usr/.ssh && cp /root/.ssh/authorized_keys /home/$usr/.ssh/ && chown -R $usr:$usr /home/$usr/.ssh && chmod 700 /home/$usr/.ssh && chmod 600 /home/$usr/.ssh/authorized_keys"
        fi
        run_step "Проверка sudo-доступа для $usr" bash -c "su - \"$usr\" -c 'sudo -n true'"
    fi
}

step4() {
    echo -e "${GREEN}== Шаг 4: SSH Configuration ==${RESET}"
    SSH_CONF=/etc/ssh/sshd_config
    run_step "Backup $SSH_CONF" backup_file "$SSH_CONF"
    rnd_port=$((RANDOM%(65535-1024)+1024))
    read -rp "Введите порт SSH [${rnd_port}]: " ssh_port; ssh_port=${ssh_port:-$rnd_port}
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
    run_step "Перезагрузка SSH-сервиса" systemctl reload "$SSH_SERVICE"
}

step5() {
    echo -e "${GREEN}== Шаг 5: Настройка UFW ==${RESET}"
    run_step "Установка UFW" apt install -y ufw
    run_step "UFW default deny incoming" ufw default deny incoming
    run_step "UFW default allow outgoing" ufw default allow outgoing
    run_step "Открытие SSH-порта $ssh_port" ufw allow "$ssh_port"/tcp
    run_step "Включение UFW" ufw --force enable
}

step6() {
    echo -e "${GREEN}== Шаг 6: Fail2ban ==${RESET}"
    run_step "Установка Fail2ban" apt install -y fail2ban
    JAIL=/etc/fail2ban/jail.local
    if [[ ! -f $JAIL ]]; then touch "$JAIL"; fi
    run_step "Backup $JAIL" backup_file "$JAIL"
    cat > "$JAIL" << EOF
[DEFAULT]
bantime.increment = true
bantime.rndtime = 30m
bantime.maxtime = 10d
findtime = 36000
maxretry = 4
banaction = iptables-multiport

[sshd]
enabled = true
port = $ssh_port
logpath = /var/log/auth.log
EOF
    run_step "Запуск и включение Fail2ban" systemctl enable --now fail2ban
}

step7() {
    echo -e "${GREEN}== Шаг 7: Swap ==${RESET}"
    swapfile=/swapfile
    if ! swapon --show | grep -q "$swapfile"; then
        run_step "Создание swapfile 2G" fallocate -l 2G "$swapfile"
        run_step "Установка прав на swapfile" chmod 600 "$swapfile"
        run_step "Инициализация swap" mkswap "$swapfile"
        run_step "Включение swap" swapon "$swapfile"
        echo "$swapfile none swap sw 0 0" >> /etc/fstab
        run_step "Настройка swappiness=10" sysctl vm.swappiness=10
        run_step "Настройка vfs_cache_pressure=50" sysctl vm.vfs_cache_pressure=50
    fi
}

step8() {
    echo -e "${GREEN}== Шаг 8: Sysctl tuning ==${RESET}"
    run_step "Backup /etc/sysctl.conf" backup_file /etc/sysctl.conf
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
    run_step "Применение sysctl" sysctl -p
}

step9() {
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
}

# Выполнение выбранных шагов
for num in $(seq 1 9); do
    if $run_all || [[ $choice == $num ]]; then
        step${num}
        # Если индивидуальный выбор — после выполнения выходим
        if ! $run_all; then break; fi
    fi
done

# Итоговый отчёт
echo -e "${GREEN}== Итоговое резюме шагов ==${RESET}"
for i in "${!actions[@]}"; do
    printf "%2d. %s\n" $((i+1)) "${actions[i]}"
done
echo -e "${GREEN}== Скрипт завершён ==${RESET}"
