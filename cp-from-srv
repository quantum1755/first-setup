#!/bin/bash
set -euo pipefail

# === Настройки ===
SSH_ALIAS="weasel"                  # Имя хоста из ~/.ssh/config
REMOTE_PATH="/home/tetsto/backups" # Путь на удаленном сервере
LOCAL_PATH="/Users/tetsto/backups"            # Локальный каталог для сохранения

# === Проверка конфигурации ===
if ! grep -q "Host ${SSH_ALIAS}" ~/.ssh/config; then
  echo "Ошибка: SSH-конфиг для '${SSH_ALIAS}' не найден!"
  exit 1
fi

# === Копирование через rsync ===
echo "Копируем ${SSH_ALIAS}:${REMOTE_PATH} -> ${LOCAL_PATH}..."
rsync -avz --progress -e "ssh" "${SSH_ALIAS}:${REMOTE_PATH}/" "${LOCAL_PATH}/"

echo "Копирование завершено!"
