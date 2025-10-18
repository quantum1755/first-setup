#!/usr/bin/env bash
# VPS Additional Setup Script
# Поддерживаемые ОС: Ubuntu, Debian
# Дополнительные настройки безопасности и оптимизации
# Резервные копии конфигов в /root/vps-additional-backup/

set -e

# Цветовая схема
GREEN="\e[32m"; YELLOW="\e[33m"; RED="\e[31m"; BLUE="\e[34m"; RESET="\e[0m"

# Массив для итогового отчёта
declare -a actions

backup_file() {
    src="$1"
    dst="/root/vps-additional-backup${src}"
    mkdir -p "$(dirname "$dst")"
    if [[ -f "$src" ]]; then
        cp -p "$src" "$dst"
        echo -e "${YELLOW}Backed up $src → $dst${RESET}"
    fi
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

# Список шагов
steps=(
    "1) Блокировка ICMP (ping)"
    "2) Включение BBR"
    "3) Установка SSL сертификата (Certbot)"
)

# Выбор шагов
echo -e "${GREEN}=== VPS Дополнительная настройка ===${RESET}"
echo -e "${YELLOW}Выберите шаг для выполнения или 'all' для всех:${RESET}"
for s in "${steps[@]}"; do echo "$s"; done
echo "all) Выполнить всё"
read -rp "Введите номер шага или all: " choice

run_all=false
if [[ $choice == "all" ]]; then run_all=true; fi

# ========== ШАГ 1: Блокировка ICMP ==========
step1() {
    echo -e "${GREEN}== Шаг 1: Блокировка ICMP (ping) ==${RESET}"
    echo -e "${YELLOW}Вы хотите заблокировать ICMP Echo Request (ping)?${RESET}"
    echo "Это повысит скрытность сервера, но усложнит диагностику сети."
    select opt in "Да, заблокировать ping" "Нет, оставить ping доступным"; do
        case $opt in
            "Да, заблокировать ping")
                # Через sysctl
                run_step "Блокировка ICMP в sysctl" bash -c "
                    echo 'net.ipv4.icmp_echo_ignore_all = 1' >> /etc/sysctl.conf
                    sysctl -p
                "
                
                # Через UFW (если используется)
                if command -v ufw &> /dev/null; then
                    run_step "Блокировка ICMP в UFW" ufw deny proto icmp from any to any
                fi
                
                # Через iptables (дополнительно)
                run_step "Блокировка ICMP в iptables" bash -c "
                    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
                    iptables-save > /etc/iptables/rules.v4
                "
                
                log_action "ICMP (ping) заблокирован"
                break
                ;;
            "Нет, оставить ping доступным")
                log_action "ICMP (ping) оставлен доступным"
                break
                ;;
        esac
    done
}

# ========== ШАГ 2: Включение BBR ==========
step2() {
    echo -e "${GREEN}== Шаг 2: Проверка и включение BBR ==${RESET}"
    echo -e "${YELLOW}BBR (Bottleneck Bandwidth and RTT) — алгоритм управления перегрузкой TCP от Google${RESET}"
    echo "Повышает производительность сети, особенно на высокоскоростных каналах."
    
    # Проверка текущего состояния
    current_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    current_qdisc=$(sysctl net.core.default_qdisc | awk '{print $3}')
    
    echo "Текущий алгоритм congestion control: $current_cc"
    echo "Текущий qdisc: $current_qdisc"
    
    if [[ "$current_cc" == "bbr" ]]; then
        echo -e "${GREEN}BBR уже включен!${RESET}"
        log_action "BBR уже был активирован"
        return
    fi
    
    # Проверка версии ядра (BBR требует 4.9+)
    kernel_version=$(uname -r | cut -d. -f1-2)
    required_version="4.9"
    
    if awk "BEGIN {exit !($kernel_version >= $required_version)}"; then
        echo -e "${GREEN}Версия ядра $kernel_version поддерживает BBR${RESET}"
        
        select opt in "Включить BBR" "Пропустить"; do
            case $opt in
                "Включить BBR")
                    backup_file /etc/sysctl.conf
                    
                    run_step "Включение BBR" bash -c "
                        echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
                        echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
                        sysctl -p
                    "
                    
                    # Проверка применения
                    new_cc=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
                    if [[ "$new_cc" == "bbr" ]]; then
                        echo -e "${GREEN}BBR успешно включен!${RESET}"
                        log_action "BBR включен и активирован"
                    else
                        echo -e "${RED}Ошибка: BBR не был активирован${RESET}"
                    fi
                    break
                    ;;
                "Пропустить")
                    log_action "Включение BBR пропущено"
                    break
                    ;;
            esac
        done
    else
        echo -e "${RED}Версия ядра $kernel_version не поддерживает BBR (требуется 4.9+)${RESET}"
        echo -e "${YELLOW}Обновите ядро для использования BBR${RESET}"
        log_action "BBR недоступен: требуется обновление ядра"
    fi
}

# ========== ШАГ 3: Certbot и SSL ==========
step3() {
    echo -e "${GREEN}== Шаг 3: Установка SSL сертификата (Certbot) ==${RESET}"
    echo -e "${YELLOW}Certbot позволяет получить бесплатный SSL сертификат от Let's Encrypt${RESET}"
    
    # Проверка установки Certbot
    if ! command -v certbot &> /dev/null; then
        echo "Certbot не установлен. Устанавливаем..."
        run_step "Установка Certbot" bash -c "apt update && apt install -y certbot"
    else
        echo -e "${GREEN}Certbot уже установлен${RESET}"
    fi
    
    # Запрос доменного имени
    read -rp "Введите доменное имя (например, example.com): " domain
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}Доменное имя не указано. Пропускаем шаг.${RESET}"
        log_action "SSL сертификат не установлен: домен не указан"
        return
    fi
    
    # Запрос email
    read -rp "Введите email для уведомлений Let's Encrypt: " email
    
    if [[ -z "$email" ]]; then
        echo -e "${RED}Email не указан. Пропускаем шаг.${RESET}"
        log_action "SSL сертификат не установлен: email не указан"
        return
    fi
    
    # Проверка доступности порта 80
    echo -e "${YELLOW}Certbot требует временный доступ к порту 80 для верификации домена${RESET}"
    
    # Открытие порта 80 временно
    if command -v ufw &> /dev/null; then
        run_step "Временное открытие порта 80 в UFW" ufw allow 80/tcp
    fi
    
    # Запрос сертификата
    run_step "Запрос SSL сертификата для $domain" certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "$email" \
        -d "$domain"
    
    # Закрытие порта 80
    if command -v ufw &> /dev/null; then
        echo -e "${YELLOW}Закрыть порт 80 после получения сертификата?${RESET}"
        select opt in "Да, закрыть порт 80" "Нет, оставить открытым"; do
            case $opt in
                "Да, закрыть порт 80")
                    run_step "Закрытие порта 80 в UFW" ufw delete allow 80/tcp
                    break
                    ;;
                "Нет, оставить открытым")
                    log_action "Порт 80 оставлен открытым"
                    break
                    ;;
            esac
        done
    fi
    
    # Создание cron-задачи для автообновления
    echo -e "${YELLOW}Настройка автоматического продления сертификата${RESET}"
    
    CRON_JOB="0 3 * * * certbot renew --pre-hook 'ufw allow 80/tcp' --post-hook 'ufw delete allow 80/tcp' --quiet"
    
    # Проверка существования задачи
    if crontab -l 2>/dev/null | grep -q "certbot renew"; then
        echo -e "${GREEN}Cron-задача для продления уже существует${RESET}"
        log_action "SSL сертификат получен, cron-задача уже настроена"
    else
        run_step "Создание cron-задачи для продления сертификата" bash -c "(crontab -l 2>/dev/null; echo '$CRON_JOB') | crontab -"
        log_action "SSL сертификат получен для $domain, настроено автопродление"
    fi
    
    # Информация о расположении сертификатов
    echo -e "${GREEN}Сертификаты установлены в:${RESET}"
    echo "  Сертификат: /etc/letsencrypt/live/$domain/fullchain.pem"
    echo "  Приватный ключ: /etc/letsencrypt/live/$domain/privkey.pem"
}

# ========== ВЫПОЛНЕНИЕ ВЫБРАННЫХ ШАГОВ ==========
for num in $(seq 1 3); do
    if $run_all || [[ $choice == $num ]]; then
        step${num}
        if ! $run_all; then break; fi
    fi
done

# ========== ИТОГОВЫЙ ОТЧЁТ ==========
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║   Итоговое резюме выполненных шагов       ║${RESET}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${RESET}"
if [[ ${#actions[@]} -eq 0 ]]; then
    echo -e "${YELLOW}Не было выполнено ни одного шага${RESET}"
else
    for i in "${!actions[@]}"; do
        printf "${BLUE}%2d.${RESET} %s\n" $((i+1)) "${actions[i]}"
    done
fi
echo ""
echo -e "${GREEN}== Скрипт завершён ==${RESET}"
