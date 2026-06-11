#!/bin/bash
# -------------------------------------------------------------------------
# 🛡️ Blitz Panel (AmneziaWG Web Panel) - Интерактивный установщик в 1 клик
# -------------------------------------------------------------------------
set -e

REPO_ARCHIVE_URL="${BLITZ_REPO_ARCHIVE_URL:-https://github.com/kuznecovpasa807-ui/Blits-Amnezia.WG/archive/refs/heads/main.tar.gz}"
INSTALL_DIR="${BLITZ_INSTALL_DIR:-/opt/blitz-amnezia-panel}"

# Цвета для вывода в терминал
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Значения по умолчанию
NON_INTERACTIVE=false
ARG_DOMAIN=""
ARG_EMAIL=""
ARG_PASSWORD=""
ARG_PORT=""

# Обработка аргументов командной строки
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes|--non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        --domain)
            ARG_DOMAIN="$2"
            shift 2
            ;;
        --email)
            ARG_EMAIL="$2"
            shift 2
            ;;
        --password)
            ARG_PASSWORD="$2"
            shift 2
            ;;
        --port)
            ARG_PORT="$2"
            shift 2
            ;;
        -h|--help)
            echo -e "${GREEN}Использование:${NC} $0 [опции]"
            echo ""
            echo -e "${YELLOW}Опции:${NC}"
            echo "  -y, --yes, --non-interactive  Установка в автоматическом режиме без вопросов"
            echo "  --domain <domain>             Использовать домен и автоматически выпустить SSL"
            echo "  --email <email>               Email для уведомлений Let's Encrypt SSL"
            echo "  --password <password>         Задать надежный пароль администратора"
            echo "  --port <port>                 Задать порт веб-панели (по умолчанию 80 для IP, 1010 для Nginx SSL)"
            echo "  -h, --help                    Показать эту справку"
            exit 0
            ;;
        *)
            echo -e "${RED}Ошибка: Неизвестный параметр $1${NC}" >&2
            exit 1
            ;;
    esac
done

wait_for_apt_locks() {
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ "$waited" -ge 300 ]; then
            echo -e "${RED}apt/dpkg is still busy after 5 minutes. Wait for system updates to finish and run install.sh again.${NC}" >&2
            return 1
        fi
        echo -e "${YELLOW}apt/dpkg is busy with system updates, waiting 10 seconds...${NC}"
        sleep 10
        waited=$((waited + 10))
    done
}

apt_update() {
    wait_for_apt_locks
    DEBIAN_FRONTEND=noninteractive apt-get update
}

apt_install() {
    wait_for_apt_locks
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

generate_web_path() {
    printf '/blits-%s\n' "$(openssl rand -hex 16)"
}

ensure_project_files() {
    if [ -f "./docker-compose.yml" ] && [ -f "./Dockerfile" ] && [ -d "./app" ] && [ -f "./install_amneziawg.sh" ]; then
        echo -e "${GREEN}Файлы проекта найдены в текущей папке: $(pwd)${NC}"
        return
    fi

    echo -e "${YELLOW}Файлы проекта рядом с install.sh не найдены. Скачиваем свежую версию с GitHub...${NC}"
    apt_update
    apt_install ca-certificates curl tar

    tmp_dir="$(mktemp -d)"
    mkdir -p "$INSTALL_DIR"
    curl_args=(-fsSL)
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl_args+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi
    curl "${curl_args[@]}" "$REPO_ARCHIVE_URL" -o "$tmp_dir/repo.tar.gz"
    tar -xzf "$tmp_dir/repo.tar.gz" -C "$tmp_dir"
    src_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d | head -n1)"
    if [ -z "$src_dir" ] || [ ! -d "$src_dir" ]; then
        echo -e "${RED}Ошибка: не удалось распаковать архив проекта.${NC}" >&2
        exit 1
    fi

    cp -a "$src_dir/." "$INSTALL_DIR/"
    rm -rf "$tmp_dir"
    cd "$INSTALL_DIR"
    echo -e "${GREEN}Проект скачан в $INSTALL_DIR${NC}"
}

clear 2>/dev/null || true
echo -e "${PURPLE}"
echo "========================================================================="
echo "   🛡️   ДОБРО ПОЖАЛОВАТЬ В УСТАНОВЩИК BLITZ PANEL & AMNEZIAWG   🛡️"
echo "========================================================================="
echo -e "${NC}"
echo -e "Этот скрипт полностью настроит AmneziaWG на вашем сервере, докеризует"
echo -e "веб-панель администратора и настроит безопасный веб-доступ (IP или SSL)."
echo ""

# Шаг 1. Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ошибка: Этот скрипт должен быть запущен от имени root (через sudo).${NC}" >&2
    exit 1
fi

# Шаг 2. Проверка операционной системы
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        echo -e "${YELLOW}Предупреждение: Установка рекомендуется на Ubuntu 22.04 / 24.04 LTS.${NC}"
        echo -e "Ваша система: $NAME ($VERSION)"
        if [ "$NON_INTERACTIVE" = true ]; then
            echo -e "${YELLOW}Автоматическое подтверждение установки в non-interactive режиме.${NC}"
        else
            read -p "Продолжить установку на свой страх и риск? (y/n): " confirm_os
            if [[ "$confirm_os" != "y" && "$confirm_os" != "Y" ]]; then
                exit 1
            fi
        fi
    fi
else
    echo -e "${YELLOW}Предупреждение: Не удалось определить ОС.${NC}"
    if [ "$NON_INTERACTIVE" = true ]; then
        echo -e "${YELLOW}Автоматическое подтверждение установки в non-interactive режиме.${NC}"
    else
        read -p "Продолжить установку? (y/n): " confirm_os
        if [[ "$confirm_os" != "y" && "$confirm_os" != "Y" ]]; then
            exit 1
        fi
    fi
fi

ensure_project_files

if [ -f "./blits" ]; then
    install -m 0755 ./blits /usr/local/bin/blits
fi

# Шаг 3. Установка системных зависимостей хоста (Docker и AmneziaWG)
echo -e "\n${BLUE}[1/5] Проверка и установка Docker & Docker Compose...${NC}"
if ! command -v docker &> /dev/null; then
    echo "Установка Docker в систему..."
    apt_update
    apt_install ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    
    # Репозиторий Docker
    if [[ "$ID" == "ubuntu" ]]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    else
        curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
        chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $VERSION_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi
    
    apt_update
    apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    echo -e "${GREEN}Docker успешно установлен!${NC}"
else
    echo -e "${GREEN}Docker уже установлен в системе.${NC}"
    # Убедимся, что служба Docker запущена и работает
    if ! systemctl is-active --quiet docker; then
        echo -e "${YELLOW}Служба Docker остановлена. Запуск службы...${NC}"
        systemctl start docker || true
        systemctl enable docker || true
    fi
fi

# Определение команды Docker Compose (docker compose или docker-compose)
DOCKER_COMPOSE_CMD="docker compose"
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD="docker-compose"
fi

echo -e "\n${BLUE}[2/5] Сборка и настройка AmneziaWG в ядре сервера...${NC}"
if [ -f "./install_amneziawg.sh" ]; then
    chmod +x install_amneziawg.sh
    # Запускаем официальную установку AmneziaWG с автоподтверждением
    bash install_amneziawg.sh --confirm
else
    echo -e "${RED}Ошибка: Не найден скрипт install_amneziawg.sh в корневой папке!${NC}"
    exit 1
fi

# Подготовка директории для БД и данных
mkdir -p data/clients data/qr

# Шаг 4. Настройка режима работы веб-панели
DOMAIN_MODE=false
PANEL_PORT=8080

if [ -n "$ARG_DOMAIN" ]; then
    DOMAIN_MODE=true
    domain_name="$ARG_DOMAIN"
    email_address="${ARG_EMAIL:-admin@$ARG_DOMAIN}"
else
    if [ "$NON_INTERACTIVE" = true ]; then
        # По умолчанию в тихом режиме - IP доступ
        DOMAIN_MODE=false
    else
        echo -e "\n${BLUE}[3/5] Настройка режима работы веб-панели:${NC}"
        echo -e "  1) Доступ по ${CYAN}IP-адресу${NC} сервера (без шифрования SSL, порт 80)"
        echo -e "  2) Доступ по ${CYAN}доменному имени${NC} (с автоматическим выпуском SSL-сертификата Let's Encrypt)"
        echo ""
        read -p "Выберите вариант (1 или 2, по умолчанию 1): " net_choice
        net_choice=${net_choice:-1}
        
        if [[ "$net_choice" == "2" ]]; then
            DOMAIN_MODE=true
            echo -e "\n--- Настройка домена и SSL ---"
            read -p "Введите ваш домен (например, vpn.mysite.com): " domain_name
            read -p "Введите ваш Email (для Let's Encrypt оповещений): " email_address
            
            if [[ -z "$domain_name" || -z "$email_address" ]]; then
                echo -e "${RED}Ошибка: Имя домена и email не могут быть пустыми! Возврат к режиму IP.${NC}"
                DOMAIN_MODE=false
            fi
        fi
    fi
fi

if [ "$DOMAIN_MODE" = true ]; then
    PANEL_PORT=${ARG_PORT:-1010} # В режиме домена запускаем панель на внутреннем порту 1010 (или кастомном)
    
    echo -e "\nУстановка Certbot для выпуска SSL-сертификата..."
    apt_install certbot
    
    # Временно освобождаем 80 порт
    systemctl stop nginx 2>/dev/null || true
    docker stop nginx-proxy 2>/dev/null || true
    docker stop amnezia-panel 2>/dev/null || true
    
    echo "Запрос бесплатного SSL-сертификата Let's Encrypt..."
    if certbot certonly --standalone -d "$domain_name" --non-interactive --agree-tos --email "$email_address"; then
        echo -e "${GREEN}SSL-сертификат успешно получен!${NC}"
        
        # Заполняем шаблон Nginx
        if [ -f "nginx.conf.template" ]; then
            sed -e "s/__DOMAIN__/$domain_name/g" -e "s/__PORT__/$PANEL_PORT/g" nginx.conf.template > nginx.conf
            echo -e "${GREEN}Файл конфигурации nginx.conf успешно создан.${NC}"
        else
            echo -e "${RED}Ошибка: Не найден шаблон nginx.conf.template!${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Ошибка выпуска SSL-сертификата! Проверьте, что домен привязан к IP этого сервера.${NC}"
        echo -e "${YELLOW}Откат на установку по IP-адресу.${NC}"
        DOMAIN_MODE=false
    fi
fi

if [ "$DOMAIN_MODE" = false ]; then
    PANEL_PORT=${ARG_PORT:-80} # В режиме IP вешаем панель напрямую на 80 веб-порт (или кастомный)
fi

# Записываем порт и секреты в файл окружения до запуска контейнера
if ! command -v openssl >/dev/null 2>&1; then
    apt_update
    apt_install openssl
fi

mkdir -p data
if [ ! -f data/panel.env ]; then
    touch data/panel.env
    chmod 600 data/panel.env
fi

EXISTING_BOT_TOKEN="$(grep -E '^TELEGRAM_API_TOKEN=' data/panel.env 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
BOT_TOKEN="${EXISTING_BOT_TOKEN:-awg_bot_api_token_$(openssl rand -hex 16)}"
SECRET_KEY_VALUE="$(grep -E '^SECRET_KEY=' data/panel.env 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
SECRET_KEY_VALUE="${SECRET_KEY_VALUE:-$(openssl rand -hex 32)}"
EXISTING_WEB_PATH="$(grep -E '^PANEL_WEB_PATH=' data/panel.env 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
WEB_PATH="${EXISTING_WEB_PATH:-$(generate_web_path)}"
PANEL_HTTPS_VALUE="0"
PANEL_DOMAIN_VALUE=""
PANEL_CERT_NAME_VALUE=""
if [ "$DOMAIN_MODE" = true ]; then
    PANEL_HTTPS_VALUE="1"
    PANEL_DOMAIN_VALUE="$domain_name"
    PANEL_CERT_NAME_VALUE="$domain_name"
fi

{
    echo "PANEL_PORT=$PANEL_PORT"
    echo "PANEL_WEB_PATH=$WEB_PATH"
    echo "PANEL_HTTPS=$PANEL_HTTPS_VALUE"
    echo "PANEL_DOMAIN=$PANEL_DOMAIN_VALUE"
    echo "PANEL_CERT_NAME=$PANEL_CERT_NAME_VALUE"
    echo "TELEGRAM_API_TOKEN=$BOT_TOKEN"
    echo "API_TOKEN=$BOT_TOKEN"
    echo "SECRET_KEY=$SECRET_KEY_VALUE"
} > data/panel.env
chmod 600 data/panel.env

# Шаг 5. Настройка пароля администратора
CUSTOM_PASS=""
if [ -n "$ARG_PASSWORD" ]; then
    CUSTOM_PASS="$ARG_PASSWORD"
else
    if [ "$NON_INTERACTIVE" = true ]; then
        # В тихом режиме автоматически генерируем надежный случайный пароль
        CUSTOM_PASS=$(openssl rand -hex 6)
    else
        echo -e "\n${BLUE}[4/5] Настройка пароля администратора:${NC}"
        echo -e "  1) Оставить пароль по умолчанию (${CYAN}admin / admin${NC})"
        echo -e "     (При первом входе в панель система принудительно попросит сменить пароль)"
        echo -e "  2) Задать надежный пароль прямо сейчас"
        echo ""
        read -p "Выберите вариант (1 или 2, по умолчанию 1): " pass_choice
        pass_choice=${pass_choice:-1}
        
        if [[ "$pass_choice" == "2" ]]; then
            echo -e "\n--- Настройка пароля ---"
            while true; do
                read -s -p "Введите новый пароль администратора: " custom_pass
                echo ""
                read -s -p "Повторите новый пароль: " custom_pass_confirm
                echo ""
                
                if [ "$custom_pass" = "$custom_pass_confirm" ]; then
                    if [ ${#custom_pass} -lt 5 ]; then
                        echo -e "${RED}Ошибка: Пароль должен содержать минимум 5 символов! Попробуйте снова.${NC}"
                    else
                        CUSTOM_PASS="$custom_pass"
                        break
                    fi
                else
                    echo -e "${RED}Ошибка: Пароли не совпадают! Попробуйте снова.${NC}"
                fi
            done
        fi
    fi
fi

# Шаг 6. Сборка и запуск Docker контейнеров
echo -e "\n${BLUE}[5/5] Запуск контейнеров в Docker...${NC}"
# Остановим старые контейнеры по именам во избежание конфликтов
docker stop amnezia-panel nginx-proxy 2>/dev/null || true
docker rm amnezia-panel nginx-proxy 2>/dev/null || true
$DOCKER_COMPOSE_CMD down || true

if [ "$DOMAIN_MODE" = true ]; then
    echo "Запуск панели с SSL-проксированием Nginx..."
    $DOCKER_COMPOSE_CMD --profile ssl up -d --build
else
    echo "Запуск панели в режиме прямого IP-доступа..."
    $DOCKER_COMPOSE_CMD up -d --build
fi

# Ожидание инициализации контейнера и базы данных
echo "Ожидание запуска контейнера amnezia-panel и инициализации БД..."
container_ready=false
for i in {1..30}; do
    if docker ps --filter "name=amnezia-panel" --filter "status=running" | grep -q "amnezia-panel"; then
        # Проверяем готовность таблицы users в SQLite
        if docker exec amnezia-panel python3 -c "
import sqlite3, os
db = '/app/data/panel.db'
if os.path.exists(db):
    try:
        conn = sqlite3.connect(db)
        cur = conn.cursor()
        cur.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='users'\")
        if cur.fetchone():
            conn.close()
            exit(0)
    except Exception:
        pass
exit(1)
" 2>/dev/null; then
            container_ready=true
            break
        fi
    fi
    sleep 1
done

if [ "$container_ready" = false ]; then
    echo -e "${RED}Внимание: Контейнер amnezia-panel не запустился вовремя или БД не готова.${NC}"
fi

echo "Проверка и синхронизация VPN-интерфейсов Amnezia 2.0 и Legacy..."
docker exec amnezia-panel python3 -c "from app.vpn_manager import rebuild_and_sync_vpn_config; rebuild_and_sync_vpn_config()" || true

# Шаг 7. Применение кастомного пароля в БД (если был выбран)
if [[ -n "$CUSTOM_PASS" ]]; then
    echo "Применение настроенного вами пароля администратора..."
    # Передаем пароль через стандартный ввод (stdin), чтобы он не светился в списке процессов
    docker exec -i amnezia-panel python3 -c "
import sys, sqlite3, bcrypt
password = sys.stdin.read().strip().encode('utf-8')
if password:
    h = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
    conn = sqlite3.connect('/app/data/panel.db')
    conn.execute('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE username = \"admin\"', (h,))
    conn.commit()
    conn.close()
" <<< "$CUSTOM_PASS"
    echo -e "${GREEN}Новый пароль успешно применен в базу данных!${NC}"
fi

# Автоматическая настройка UFW, если он активен
if ufw status | grep -q "Status: active"; then
    echo -e "\n${BLUE}Настройка брандмауэра UFW...${NC}"
    if [ "$DOMAIN_MODE" = true ]; then
        echo "Разрешаем входящий TCP трафик для HTTP/HTTPS (порты 80, 443)..."
        ufw allow 80/tcp
        ufw allow 443/tcp
    else
        echo "Разрешаем входящий TCP трафик для веб-панели (порт $PANEL_PORT)..."
        ufw allow "$PANEL_PORT/tcp"
    fi
    ufw reload
fi

# Вывод красивого финального баннера
PUBLIC_IP=$(curl -s https://ifconfig.me || curl -s https://api.ipify.org)

echo -e "\n${GREEN}========================================================================="
echo "   🎉   УСТАНОВКА И НАСТРОЙКА BLITZ PANEL УСПЕШНО ЗАВЕРШЕНА!   🎉"
echo "=========================================================================${NC}"
echo ""
echo -e "Адрес панели в вашем браузере:"
if [ "$DOMAIN_MODE" = true ]; then
    echo -e "  🔗  ${CYAN}https://$domain_name$WEB_PATH${NC}"
else
    echo -e "  🔗  ${CYAN}http://$PUBLIC_IP$WEB_PATH${NC}"
fi
echo ""
echo -e "Данные для входа в надежную панель:"
echo -e "  👤  Имя пользователя: ${CYAN}admin${NC}"
if [[ -n "$CUSTOM_PASS" ]]; then
    if [ "$NON_INTERACTIVE" = true ]; then
        echo -e "  🔑  Пароль:           ${GREEN}$CUSTOM_PASS${NC} (сохраните его!)"
    else
        echo -e "  🔑  Пароль:           ${CYAN}[Установлен ваш личный надежный пароль]${NC}"
    fi
else
    echo -e "  🔑  Пароль:           ${CYAN}admin${NC} (система сразу потребует его смену)"
fi
echo ""
echo -e "Для API-интеграции с Telegram-ботом используйте Bearer Token:"
echo -e "  🤖  ${YELLOW}$BOT_TOKEN${NC}"
echo ""
echo -e "Служба панели работает стабильно в Docker-контейнере."
echo -e "Увидеть логи панели можно командой: ${PURPLE}docker logs -f amnezia-panel${NC}"
echo -e "${GREEN}=========================================================================${NC}\n"
