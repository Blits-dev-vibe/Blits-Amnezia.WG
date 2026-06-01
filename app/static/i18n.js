(function () {
    function getCookie(name) {
        return document.cookie
            .split('; ')
            .find((row) => row.startsWith(name + '='))
            ?.split('=')[1] || '';
    }

    const lang = decodeURIComponent(getCookie('panel_lang') || 'ru');
    if (lang !== 'en') return;

    const dict = {
        'Панель управления': 'Dashboard',
        'Клиенты': 'Clients',
        'Настройки': 'Settings',
        'Смена пароля': 'Change password',
        'Настройки VPN': 'VPN settings',
        'Каскад': 'Cascade',
        'Настройки панели': 'Panel settings',
        'API Документация': 'API documentation',
        'API': 'API',
        'Выйти': 'Log out',
        'Создать клиента': 'Create client',
        'Поиск': 'Search',
        'Полный туннель': 'Full tunnel',
        'Раздельный': 'Split tunnel',
        'Конфигурация ключа': 'Client configuration',
        'QR-коды для AmneziaVPN': 'QR codes for AmneziaVPN',
        'Сканируй все части одной версии по порядку.': 'Scan all parts of one version in order.',
        'Конфигурация AmneziaWG:': 'AmneziaWG configuration:',
        'Копировать конфиг': 'Copy config',
        'Скачать .conf': 'Download .conf',
        'Ссылка для импорта в приложение:': 'Import link for the app:',
        'Импорт': 'Import',
        'Закрыть': 'Close',
        'Доступ к веб-панели': 'Web panel access',
        'Порт панели': 'Panel port',
        'Домен панели': 'Panel domain',
        'Тема панели': 'Panel theme',
        'Светлая': 'Light',
        'Тёмная': 'Dark',
        'Язык панели': 'Panel language',
        'Уведомления админу': 'Admin notifications',
        'Отправлять события в Telegram': 'Send events to Telegram',
        'Токен бота': 'Bot token',
        'Chat ID администратора': 'Admin chat ID',
        'Сохранить': 'Save',
        'Скачать бэкап': 'Download backup',
        'Отмена': 'Cancel',
        'Загрузка...': 'Loading...',
        'QR недоступен': 'QR unavailable',
        'Не удалось сгенерировать ссылку': 'Could not generate link'
    };

    window.panelT = function (text) {
        return dict[text] || text;
    };

    function translateTextNode(node) {
        const value = node.nodeValue;
        const trimmed = value.trim();
        if (!trimmed || !dict[trimmed]) return;
        node.nodeValue = value.replace(trimmed, dict[trimmed]);
    }

    function walk(root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                const parent = node.parentElement;
                if (!parent || ['SCRIPT', 'STYLE', 'TEXTAREA', 'CODE', 'PRE'].includes(parent.tagName)) {
                    return NodeFilter.FILTER_REJECT;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        let node;
        while ((node = walker.nextNode())) {
            translateTextNode(node);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => walk(document.body));
    } else {
        walk(document.body);
    }
})();
