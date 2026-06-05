#!/bin/bash
# Скрипт установки AmneziaWG для AmneziaWG Web Panel MVP
set -e

echo "=== УСТАНОВКА AMNEZIAWG ==="

# Проверка на root
if [ "$EUID" -ne 0 ]; then
  echo "Ошибка: Этот скрипт должен быть запущен от имени root." >&2
  exit 1
fi

# Проверка подтверждения
if [ "$1" != "--confirm" ]; then
  echo "ВНИМАНИЕ! Этот скрипт внесет следующие изменения в вашу систему:"
  echo "1. Добавит PPA-репозиторий ppa:amnezia/ppa"
  echo "2. Установит пакеты amneziawg и amneziawg-tools"
  echo "3. Включит форвардинг IPv4/IPv6 пакетов (sysctl net.ipv4.ip_forward=1)"
  echo "4. Автоматически определит публичный сетевой интерфейс"
  echo "5. Создаст базовый конфигурационный файл /etc/amnezia/amneziawg/awg0.conf"
  echo ""
  echo "Если вы согласны, запустите скрипт с флагом: $0 --confirm"
  exit 0
fi

# Проверяем, установлен ли уже awg
if command -v awg >/dev/null 2>&1; then
  echo "AmneziaWG (awg) уже установлен в системе. Пропускаем шаг установки пакетов."
else
  echo "Обновление пакетного менеджера и установка базовых утилит..."
  apt-get update
  apt-get install -y software-properties-common iptables ufw curl

  echo "Добавление PPA репозитория AmneziaWG..."
  add-apt-repository -y ppa:amnezia/ppa

  # Если дистрибутив resolute (Ubuntu 26.04), подменяем кодовое имя на noble, так как для 26.04 еще нет официальной сборки в PPA
  if grep -q "resolute" /etc/apt/sources.list.d/amnezia-ubuntu-ppa-*.list 2>/dev/null; then
    echo "Обнаружена Ubuntu 26.04 (Resolute). Подменяем кодовое имя репозитория на noble..."
    sed -i 's/resolute/noble/g' /etc/apt/sources.list.d/amnezia-ubuntu-ppa-*.list 2>/dev/null || true
  fi

  apt-get update

  echo "Установка amneziawg..."
  apt-get install -y amneziawg
fi

# Включение форвардинга пакетов
echo "Включение форвардинга IPv4 и IPv6 пакетов..."
sysctl -w net.ipv4.ip_forward=1
# Включаем IPv6 форвардинг только если система поддерживает IPv6
if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
    sysctl -w net.ipv6.conf.all.forwarding=1
fi

# Сохранение в sysctl.conf
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
  echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
fi

# Определение основного сетевого интерфейса
DEFAULT_INTERFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [ -z "$DEFAULT_INTERFACE" ]; then
  DEFAULT_INTERFACE="eth0"
  echo "Предупреждение: Не удалось автоматически определить сетевой интерфейс. Используется по умолчанию: eth0"
else
  echo "Определен основной сетевой интерфейс: $DEFAULT_INTERFACE"
fi

# Создание директории для конфигураций AmneziaWG
mkdir -p /etc/amnezia/amneziawg

# Генерация ключей сервера, если они еще не существуют
PRIVATE_KEY_FILE="/etc/amnezia/amneziawg/server.key"
PUBLIC_KEY_FILE="/etc/amnezia/amneziawg/server.pub"

if [ ! -f "$PRIVATE_KEY_FILE" ]; then
  echo "Генерация ключей сервера AmneziaWG..."
  awg genkey | tee "$PRIVATE_KEY_FILE" | awg pubkey > "$PUBLIC_KEY_FILE"
  chmod 600 "$PRIVATE_KEY_FILE"
  echo "Ключи успешно сгенерированы."
else
  echo "Ключи сервера уже существуют. Используем существующие."
fi

SERVER_PRIVATE_KEY=$(cat "$PRIVATE_KEY_FILE")
SERVER_PUBLIC_KEY=$(cat "$PUBLIC_KEY_FILE")
LEGACY_PRIVATE_KEY_FILE="/etc/amnezia/amneziawg/server_legacy.key"
LEGACY_PUBLIC_KEY_FILE="/etc/amnezia/amneziawg/server_legacy.pub"
LEGACY_INTERFACE="awg_legacy"
LEGACY_CONFIG_FILE="/etc/amnezia/amneziawg/${LEGACY_INTERFACE}.conf"
LEGACY_PORT="43913"

if [ ! -f "$LEGACY_PRIVATE_KEY_FILE" ]; then
  echo "Генерация отдельного ключа сервера для Amnezia Legacy..."
  awg genkey | tee "$LEGACY_PRIVATE_KEY_FILE" | awg pubkey > "$LEGACY_PUBLIC_KEY_FILE"
  chmod 600 "$LEGACY_PRIVATE_KEY_FILE"
else
  echo "Legacy-ключи сервера уже существуют. Используем существующие."
fi

LEGACY_PRIVATE_KEY=$(cat "$LEGACY_PRIVATE_KEY_FILE")
LEGACY_PUBLIC_KEY=$(cat "$LEGACY_PUBLIC_KEY_FILE")

# Создание базового конфига awg0.conf
CONFIG_FILE="/etc/amnezia/amneziawg/awg0.conf"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Создание конфигурационного файла $CONFIG_FILE..."
  cat > "$CONFIG_FILE" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY

# Параметры маскировки AmneziaWG (Junk Packet Parameters)
Jc = 4
Jmin = 10
Jmax = 50
S1 = 61
S2 = 34
S3 = 21
S4 = 2
H1 = 906396796-1598714541
H2 = 2056848576-2126223526
H3 = 2141047196-2144456894
H4 = 2146243463-2147170402

PostUp = iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; iptables -A FORWARD -i awg0 -j ACCEPT; iptables -A FORWARD -o awg0 -j ACCEPT; ip6tables -A FORWARD -i awg0 -j ACCEPT; ip6tables -A FORWARD -o awg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; iptables -D FORWARD -i awg0 -j ACCEPT; iptables -D FORWARD -o awg0 -j ACCEPT; ip6tables -D FORWARD -i awg0 -j ACCEPT; ip6tables -D FORWARD -o awg0 -j ACCEPT
EOF
  chmod 600 "$CONFIG_FILE"
  echo "Базовый конфиг awg0.conf успешно создан."
else
  echo "Конфигурационный файл $CONFIG_FILE уже существует. Пропускаем создание."
fi

# Создание отдельного базового конфига для Amnezia 1 / Legacy.
# Legacy намеренно не содержит S3/S4/I*-параметры, поэтому ему нужен отдельный порт и интерфейс.
if [ ! -f "$LEGACY_CONFIG_FILE" ]; then
  echo "Создание Legacy-конфигурации $LEGACY_CONFIG_FILE..."
  cat > "$LEGACY_CONFIG_FILE" <<EOF
[Interface]
Address = 10.66.67.1/24
ListenPort = $LEGACY_PORT
PrivateKey = $LEGACY_PRIVATE_KEY

# Legacy AmneziaWG: базовая обфускация без параметров Amnezia 2.0
Jc = 4
Jmin = 10
Jmax = 50
S1 = 61
S2 = 34
H1 = 906396796-1598714541
H2 = 2056848576-2126223526
H3 = 2141047196-2144456894
H4 = 2146243463-2147170402

PostUp = iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; iptables -A FORWARD -i $LEGACY_INTERFACE -j ACCEPT; iptables -A FORWARD -o $LEGACY_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE; iptables -D FORWARD -i $LEGACY_INTERFACE -j ACCEPT; iptables -D FORWARD -o $LEGACY_INTERFACE -j ACCEPT
EOF
  chmod 600 "$LEGACY_CONFIG_FILE"
  echo "Legacy-конфиг успешно создан."
else
  echo "Legacy-конфигурационный файл $LEGACY_CONFIG_FILE уже существует. Пропускаем создание."
fi

# Настройка правил брандмауэра UFW, если он включен
if ufw status | grep -q "Status: active"; then
  echo "UFW активен. Добавляем разрешение для UDP порта 51820..."
  ufw allow 51820/udp
  ufw allow ${LEGACY_PORT}/udp
  ufw route allow in on awg0
  ufw route allow in on $LEGACY_INTERFACE
  ufw reload
fi

# Включение и запуск сервиса AmneziaWG
echo "Включение и запуск сервиса awg-quick@awg0..."
systemctl enable awg-quick@awg0 || echo "Предупреждение: Не удалось включить автозапуск awg-quick@awg0."
systemctl restart awg-quick@awg0 || echo "Предупреждение: Не удалось перезапустить awg-quick@awg0 (может потребоваться перезагрузка)."
echo "Включение и запуск сервиса awg-quick@${LEGACY_INTERFACE}..."
systemctl enable "awg-quick@${LEGACY_INTERFACE}" || echo "Предупреждение: Не удалось включить автозапуск awg-quick@${LEGACY_INTERFACE}."
systemctl restart "awg-quick@${LEGACY_INTERFACE}" || echo "Предупреждение: Не удалось перезапустить awg-quick@${LEGACY_INTERFACE}."

echo "=== УСТАНОВКА И НАСТРОЙКА AMNEZIAWG ЗАВЕРШЕНА ==="
echo "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
echo "Публичный Legacy-ключ сервера: $LEGACY_PUBLIC_KEY"
