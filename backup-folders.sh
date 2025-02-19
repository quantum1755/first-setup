#!/bin/bash
set -euo pipefail  # Прерываем выполнение при ошибке или необъявленной переменной

# === Настройки скрипта ===

# Каталог для сохранения tar‑файлов (если не существует, будет создан)
BACKUP_DIR="/home/tetsto/backups"  # Замените на нужный путь

# Директория, куда будут скопированы архивы (например, путь к другому диску)
DESTINATION_DIR="/path/to/destination_disk"  # Замените на путь к другому диску

# Текущая дата для включения в имя файла
DATE=$(date +"%Y-%m-%d")

# Новый владелец для созданных архивов (можно указать и группу, например: "username:group")
NEW_OWNER="tetsto:"  # Замените username на требуемого пользователя (или "username:group")

# Список каталогов для резервного копирования
# Формат: ["имя_архива"]="путь_к_каталогу"
declare -A BACKUPS=(
  ["wireguard"]="/etc/wireguard"
  ["wireguard-conf"]="/home/tetsto/wireguard"
  ["openvpn"]="/etc/openvpn"
  ["easy-rsa"]="/home/tetsto/easy-rsa"
  ["ovpn-client-configs"]="/home/tetsto/client-configs"
)

# Создаём каталог для резервных копий, если он не существует
mkdir -p "${BACKUP_DIR}"
mkdir -p "${DESTINATION_DIR}"

# === Функция для создания резервной копии и установки владельца файла ===
create_backup() {
  local name="$1"
  local src_path="$2"
  local archive_path="${BACKUP_DIR}/${name}-${DATE}.tar"
  
  echo "Создаётся резервная копия каталога '${src_path}' в '${archive_path}'..."
  tar -cpf "${archive_path}" "${src_path}"
  
  echo "Устанавливаем владельца '${NEW_OWNER}' для файла '${archive_path}'..."
  chown "${NEW_OWNER}" "${archive_path}"
}

# === Основной блок скрипта ===
for name in "${!BACKUPS[@]}"; do
  src="${BACKUPS[$name]}"
  if [ -d "${src}" ]; then
    create_backup "${name}" "${src}"
  else
    echo "Предупреждение: каталог '${src}' не найден. Пропускаем резервное копирование '${name}'."
  fi
done

# Удаляем резервные копии старше 30 дней
echo "Удаляем файлы резервных копий старше 30 дней..."
find "${BACKUP_DIR}" -name '*.tar' -type f -mtime +30 -delete

echo "Все резервные копии успешно созданы, и владельцы файлов установлены."

# === Копирование архивов на другой диск ===
echo "Копирование созданных резервных копий в '${DESTINATION_DIR}'..."
cp -r "${BACKUP_DIR}"/*.tar "${DESTINATION_DIR}/"

# Удаляем резервные копии старше 30 дней
echo "Удаляем файлы резервных копий из второго диска старше 30 дней..."
find "${DESTINATION_DIR}" -name '*.tar' -type f -mtime +30 -delete

echo "Копирование архивов завершено."
