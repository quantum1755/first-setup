#!/bin/bash
# setup_server.sh – интерактивная настройка Debian-сервера

LOGFILE="$(dirname "$(realpath "$0")")/setup_server.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "=========================================="
echo "Первоначальная настройка сервера Debian"
echo "Дата: $(date)"
echo "=========================================="

#############################################
# 1. Обновление пакетов и установка sudo, nano
#############################################
echo "[1/10] Обновление пакетов и установка sudo, nano..."
apt update && apt upgrade -y
apt install -y sudo nano ufw certbot python3-certbot-nginx
echo "Обновление завершено."

#############################################
# 2. Изменение имени хоста
#############################################
read -rp "Введите новое имя хоста: " NEW_HOSTNAME
hostnamectl set-hostname "$NEW_HOSTNAME"
sed -i "s/127.0.1.1.*/127.0.1.1   $NEW_HOSTNAME/" /etc/hosts
echo "Имя хоста изменено на '$NEW_HOSTNAME'."

#############################################
# 3. Создание пользователя tetsto с sudo и SSH
#############################################
echo "[3/10] Создание пользователя tetsto..."
adduser --gecos "" tetsto
usermod -aG sudo tetsto
mkdir -p /home/tetsto/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvqTzJ8rHh5ibhY6zLjEmc0m8Q3tVVgd2CLy5LEXWSxV7URoIgKgsryNcL3oaeBy/02C7xSh3npFbwLo1oQ327LLxK7wsNv04Bpd452sT/Nu70wHzQRHJaa9JnI7Ok8G/4ALOxgeaZPYCZBAnwh4mHU0zpw1rW/wiVifMkWgZY8UIQ8JL3+2UtYNXU8MkUpKknBEecWvXmF5SK9vGCGKxBE+3snMEz3j3f+KeWIGtv7c+UBszCTHxEyKZaQe8zcfmJyxTYua13Xr6y3r9qienJjKIi/PnL82k31PLhhc36mLjJeaPApj5RpgzPAZ2HlMjmplVJ0XXRMyOhH8RFsFHl tetsto@ServerLinux" > /home/tetsto/.ssh/authorized_keys
chmod 600 /home/tetsto/.ssh/authorized_keys
chown -R tetsto:tetsto /home/tetsto/.ssh
echo "Пользователь tetsto создан."

#############################################
# 4. Включение IP-форвардинга
#############################################
echo "[4/10] Включение IP-форвардинга..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
echo "IP-форвардинг включен."

#############################################
# 5. Проверка и настройка BBR
#############################################
echo "[5/10] Проверка BBR..."
BBR_STATUS=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
if [[ "$BBR_STATUS" == "bbr" ]]; then
    echo "BBR уже включён."
else
    read -rp "Включить BBR? (y/n): " ENABLE_BBR
    if [[ "$ENABLE_BBR" == "y" ]]; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        echo "BBR включен."
    else
        echo "BBR не изменён."
    fi
fi

#############################################
# 6. Настройка UFW
#############################################
echo "[6/10] Настройка брандмауэра (UFW)..."
ufw default deny incoming
ufw default allow outgoing
for port in 443 49270 27961 2120; do
    ufw allow "$port"
done
ufw enable
echo "Брандмауэр настроен."

#############################################
# 7. Изменение порта SSH
#############################################
echo "[7/10] Изменение порта SSH на 2120..."
sed -i "s/^#Port 22/Port 2120/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port 2120/" /etc/ssh/sshd_config
ufw allow 2120
systemctl restart sshd
echo "Порт SSH изменён."

#############################################
# 8. Установка сертификата Let's Encrypt
#############################################
read -rp "Хотите установить SSL-сертификат? (y/n): " INSTALL_SSL
if [[ "$INSTALL_SSL" == "y" ]]; then
    read -rp "Введите домен: " DOMAIN
    read -rp "Введите email: " EMAIL
    certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive
    echo "Сертификат установлен."
    echo "Создание cron-задачи для обновления..."
    echo "0 3 * * * root ufw allow 80 && certbot renew && ufw deny 80" > /etc/cron.d/certbot-renew
    echo "Cron-задача добавлена."
else
    echo "Пропущена установка сертификата."
fi

#############################################
# 9. Добавление SSH-ключа и отключение паролей
#############################################
echo "[9/10] Отключение паролей для SSH..."
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvqTzJ8rHh5ibhY6zLjEmc0m8Q3tVVgd2CLy5LEXWSxV7URoIgKgsryNcL3oaeBy/02C7xSh3npFbwLo1oQ327LLxK7wsNv04Bpd452sT/Nu70wHzQRHJaa9JnI7Ok8G/4ALOxgeaZPYCZBAnwh4mHU0zpw1rW/wiVifMkWgZY8UIQ8JL3+2UtYNXU8MkUpKknBEecWvXmF5SK9vGCGKxBE+3snMEz3j3f+KeWIGtv7c+UBszCTHxEyKZaQe8zcfmJyxTYua13Xr6y3r9qienJjKIi/PnL82k31PLhhc36mLjJeaPApj5RpgzPAZ2HlMjmplVJ0XXRMyOhH8RFsFHl tetsto@ServerLinux" >> /root/.ssh/authorized_keys
sed -i "s/^#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
systemctl restart sshd
echo "Парольная аутентификация отключена."

echo "✅ Настройка завершена!"
