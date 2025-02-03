#!/bin/bash
# Скрипт первоначальной настройки VPN-сервера:
# 1. Обновление пакетов
# 2. Изменение имени хоста
# 3. Создание пользователей (tetsto с правами sudo и dockeruser)
# 4. Разрешение IP-форвардинга
# 5. Проверка и включение BBR
# 6. Настройка firewall (ufw): установка режима по умолчанию и разрешение необходимых портов
# 7. Опциональная блокировка пинга (ICMP Echo Request)
# 8. Установка и запрос сертификата с помощью certbot для домена nossobaki25.duckdns.org,
#    а также создание cron-задачи для продления сертификата с временным открытием порта 80
# 9. Настройка SSH: изменение порта с 22 на 2120, добавление открытого SSH-ключа для root и tetsto,
#    отключение аутентификации по паролю
# 10. Вывод итоговой информации с логом выполнения

LOGFILE="/var/log/vpn_setup.log"
: > "$LOGFILE"  # очищаем лог-файл

# Задайте открытый SSH-ключ, который будет добавлен для пользователей root и tetsto
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvqTzJ8rHh5ibhY6zLjEmc0m8Q3tVVgd2CLy5LEXWSxV7URoIgKgsryNcL3oaeBy/02C7xSh3npFbwLo1oQ327LLxK7wsNv04Bpd452sT/Nu70wHzQRHJaa9JnI7Ok8G/4ALOxgeaZPYCZBAnwh4mHU0zpw1rW/wiVifMkWgZY8UIQ8JL3+2UtYNXU8MkUpKknBEecWvXmF5SK9vGCGKxBE+3snMEz3j3f+KeWIGtv7c+UBszCTHxEyKZaQe8zcfmJyxTYua13Xr6y3r9qienJjKIi/PnL82k31PLhhc36mLjJeaPApj5RpgzPAZ2HlMjmplVJ0XXRMyOhH8RFsFHl tetsto@ServerLinux"

# Опция блокировки пинга: если установлено значение "yes", то сервер не будет отвечать на ICMP Echo Request.
BLOCK_PING="yes"  # установите "no", чтобы оставить пинг включённым

# Домен для сертификата и email администратора (замените email при необходимости)
DOMAIN="nossobaki25.duckdns.org"
ADMIN_EMAIL="admin@nossobaki25.duckdns.org"

# Функция логирования
log() {
    local type="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$type] $message" | tee -a "$LOGFILE"
}

# Проверка, что скрипт запущен от имени root
if [[ $EUID -ne 0 ]]; then
    log "ERROR" "Скрипт должен выполняться от имени root"
    exit 1
fi

##############################################
# 1. Обновление пакетов
##############################################
log "INFO" "Начинается обновление пакетов..."
if apt-get update -y >> "$LOGFILE" 2>&1 && apt-get upgrade -y >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "Пакеты успешно обновлены"
else
    log "ERROR" "Ошибка при обновлении пакетов"
fi

##############################################
# 2. Изменение имени хоста
##############################################
NEW_HOSTNAME="vpn-server"   # Задайте нужное имя хоста
log "INFO" "Изменение имени хоста на $NEW_HOSTNAME..."
if hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "Имя хоста успешно изменено на $NEW_HOSTNAME"
else
    log "ERROR" "Ошибка при изменении имени хоста"
fi

##############################################
# 3. Создание пользователей
##############################################
create_user() {
    local username="$1"
    local sudo_flag="$2"  # Если передано "sudo", то добавить в группу sudo
    log "INFO" "Создание пользователя $username..."
    if id "$username" &>/dev/null; then
        log "WARNING" "Пользователь $username уже существует"
    else
        if useradd -m -s /bin/bash "$username" >> "$LOGFILE" 2>&1; then
            log "SUCCESS" "Пользователь $username успешно создан"
            # Принудительная смена пароля при первом входе
            passwd -e "$username" >> "$LOGFILE" 2>&1
            if [[ "$sudo_flag" == "sudo" ]]; then
                usermod -aG sudo "$username" >> "$LOGFILE" 2>&1
                if [[ $? -eq 0 ]]; then
                    log "SUCCESS" "Пользователь $username добавлен в группу sudo"
                else
                    log "ERROR" "Ошибка при добавлении пользователя $username в группу sudo"
                fi
            fi
        else
            log "ERROR" "Ошибка при создании пользователя $username"
        fi
    fi
}

# Создаём пользователя tetsto с правами sudo
create_user "tetsto" "sudo"
# Создаём дополнительного пользователя (например, dockeruser)
create_user "dockeruser" ""

##############################################
# 4. Разрешение IP-форвардинга
##############################################
log "INFO" "Настройка IP-форвардинга..."
if sysctl -w net.ipv4.ip_forward=1 >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "IP-форвардинг включён (текущая сессия)"
else
    log "ERROR" "Ошибка при включении IP-форвардинга"
fi

if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
    sed -i 's/^net\.ipv4\.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
else
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
fi
if sysctl -p >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "Постоянная настройка IP-форвардинга применена"
else
    log "ERROR" "Ошибка при применении настроек IP-форвардинга"
fi

##############################################
# 5. Проверка и включение BBR
##############################################
log "INFO" "Проверка наличия BBR..."
CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control 2>>"$LOGFILE" | awk '{print $3}')
if [[ "$CURRENT_CC" == "bbr" ]]; then
    log "SUCCESS" "BBR уже включён (текущий алгоритм: $CURRENT_CC)"
else
    log "WARNING" "BBR не включён (текущий алгоритм: $CURRENT_CC). Пытаемся включить BBR..."
    grep -q "^net.core.default_qdisc" /etc/sysctl.conf && \
      sed -i 's/^net\.core\.default_qdisc.*/net.core.default_qdisc = fq/' /etc/sysctl.conf || \
      echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf

    grep -q "^net.ipv4.tcp_congestion_control" /etc/sysctl.conf && \
      sed -i 's/^net\.ipv4\.tcp_congestion_control.*/net.ipv4.tcp_congestion_control = bbr/' /etc/sysctl.conf || \
      echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf

    if sysctl -p >> "$LOGFILE" 2>&1; then
        NEW_CC=$(sysctl net.ipv4.tcp_congestion_control 2>>"$LOGFILE" | awk '{print $3}')
        if [[ "$NEW_CC" == "bbr" ]]; then
            log "SUCCESS" "BBR успешно включён (текущий алгоритм: $NEW_CC)"
        else
            log "ERROR" "Не удалось включить BBR. Текущий алгоритм: $NEW_CC"
        fi
    else
        log "ERROR" "Ошибка при применении настроек для BBR"
    fi
fi

##############################################
# 6. Настройка firewall (ufw)
##############################################
log "INFO" "Настройка ufw: установка режима по умолчанию и разрешение необходимых портов..."
# Установка ufw, если он не установлен
if ! command -v ufw &>/dev/null; then
    if apt-get install -y ufw >> "$LOGFILE" 2>&1; then
        log "SUCCESS" "ufw успешно установлен"
    else
        log "ERROR" "Ошибка установки ufw"
    fi
fi

# Устанавливаем режимы по умолчанию:
# Входящие соединения запрещены, исходящие разрешены
ufw default deny incoming >> "$LOGFILE" 2>&1
ufw default allow outgoing >> "$LOGFILE" 2>&1
log "SUCCESS" "Режим по умолчанию: входящие соединения запрещены, исходящие разрешены"

# Разрешаем необходимые порты:
# SSH: 2120, остальные: 49270, 27961, 443
for port in 2120 49270 27961 443; do
    if ufw allow "$port" >> "$LOGFILE" 2>&1; then
        log "SUCCESS" "Порт $port открыт в ufw"
    else
        log "ERROR" "Ошибка при открытии порта $port в ufw"
    fi
done

# Порт 80 не разрешается постоянно – он будет открываться для certbot
if ufw --force enable >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "ufw успешно включён"
else
    log "ERROR" "Ошибка при включении ufw"
fi

##############################################
# 7. Опциональная блокировка пинга (ICMP Echo Request)
##############################################
if [[ "$BLOCK_PING" == "yes" ]]; then
    log "INFO" "Блокировка пинга включена. Добавляю правило для блокировки ICMP Echo Request..."
    if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null; then
        log "INFO" "Правило для блокировки пинга уже существует"
    else
        if iptables -A INPUT -p icmp --icmp-type echo-request -j DROP >> "$LOGFILE" 2>&1; then
            log "SUCCESS" "Правило для блокировки пинга успешно добавлено"
        else
            log "ERROR" "Ошибка при добавлении правила для блокировки пинга"
        fi
    fi
else
    log "INFO" "Блокировка пинга отключена. Пинги будут обрабатываться стандартно."
fi

##############################################
# 8. Установка certbot и запрос сертификата
##############################################
log "INFO" "Установка certbot..."
if apt-get install -y certbot >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "certbot успешно установлен"
else
    log "ERROR" "Ошибка установки certbot"
fi

log "INFO" "Запрос сертификата для домена $DOMAIN..."
# Временное открытие порта 80 для certbot (если правило отсутствует)
if ! ufw status numbered | grep -q "80/tcp"; then
    ufw allow 80 >> "$LOGFILE" 2>&1
    log "INFO" "Временно открыт порт 80 для получения сертификата"
fi

# Запрос сертификата с использованием standalone-режима
if certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$ADMIN_EMAIL" >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "Сертификат для домена $DOMAIN успешно запрошен"
else
    log "ERROR" "Ошибка запроса сертификата для домена $DOMAIN"
fi

# Закрываем порт 80 после запроса сертификата
ufw delete allow 80 >> "$LOGFILE" 2>&1
log "INFO" "Порт 80 закрыт после запроса сертификата"

# Создаём скрипт для продления сертификата с временным открытием порта 80
CERTBOT_RENEW_SCRIPT="/usr/local/bin/certbot-renew.sh"
cat > "$CERTBOT_RENEW_SCRIPT" << 'EOF'
#!/bin/bash
# Открываем порт 80 для продления сертификата
ufw allow 80
# Выполняем продление сертификата
certbot renew --quiet
# Закрываем порт 80 после продления
ufw delete allow 80
EOF
chmod +x "$CERTBOT_RENEW_SCRIPT"
log "SUCCESS" "Скрипт для продления сертификата создан: $CERTBOT_RENEW_SCRIPT"

# Добавляем cron-задачу для продления сертификата (пример: каждый день в 3:00)
CRON_FILE="/etc/cron.d/certbot-renew"
cat > "$CRON_FILE" << EOF
0 3 * * * root $CERTBOT_RENEW_SCRIPT >> /var/log/certbot-renew.log 2>&1
EOF
chmod 644 "$CRON_FILE"
log "SUCCESS" "Cron-задача для продления сертификата добавлена: $CRON_FILE"

##############################################
# 9. Настройка SSH: изменение порта, установка ключей и отключение аутентификации по паролю
##############################################
SSH_CONFIG="/etc/ssh/sshd_config"

# Изменяем порт SSH на 2120: если строка Port уже присутствует, меняем её; иначе добавляем
if grep -q "^Port" "$SSH_CONFIG"; then
    sed -i 's/^Port.*/Port 2120/' "$SSH_CONFIG"
else
    echo "Port 2120" >> "$SSH_CONFIG"
fi
log "SUCCESS" "Порт SSH изменён на 2120 в $SSH_CONFIG"

# Добавление открытого SSH-ключа для пользователей root и tetsto
add_ssh_key() {
    local username="$1"
    if [ "$username" == "root" ]; then
        HOME_DIR="/root"
    else
        HOME_DIR="/home/$username"
    fi
    SSH_DIR="$HOME_DIR/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"
    log "INFO" "Добавление SSH-ключа для пользователя $username..."
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR" >> "$LOGFILE" 2>&1
        chown "$username":"$username" "$SSH_DIR"
        chmod 700 "$SSH_DIR"
    fi
    if [ -f "$AUTH_KEYS" ]; then
        if grep -qF "$SSH_PUBLIC_KEY" "$AUTH_KEYS"; then
            log "INFO" "SSH-ключ для пользователя $username уже установлен"
        else
            echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
            log "SUCCESS" "SSH-ключ для пользователя $username успешно добавлен"
        fi
    else
        echo "$SSH_PUBLIC_KEY" > "$AUTH_KEYS"
        chown "$username":"$username" "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        log "SUCCESS" "SSH-ключ для пользователя $username успешно добавлен"
    fi
}
add_ssh_key "root"
add_ssh_key "tetsto"

# Отключение аутентификации по паролю
if grep -q "^#\?PasswordAuthentication" "$SSH_CONFIG"; then
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$SSH_CONFIG"
else
    echo "PasswordAuthentication no" >> "$SSH_CONFIG"
fi
log "SUCCESS" "Аутентификация по паролю отключена в $SSH_CONFIG"

# Перезагружаем службу SSH для применения изменений
if systemctl reload sshd >> "$LOGFILE" 2>&1; then
    log "SUCCESS" "SSH-сервер успешно перезагружен"
else
    log "ERROR" "Ошибка при перезагрузке SSH-сервера"
fi

##############################################
# 10. Вывод итоговой информации
##############################################
echo -e "\n===== Итоговая информация ====="
cat "$LOGFILE"
echo "===== Конец работы скрипта ====="
