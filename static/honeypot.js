/**
 * Invisible Honeypot для Telegram WebApp
 * 
 * Добавляет невидимые ловушки, которые активируют только боты.
 * Люди не видят эти элементы и не взаимодействуют с ними.
 * 
 * Использование:
 *   <script src="honeypot.js"></script>
 *   <script>addHoneypotTraps();</script>
 */

// Конфигурация
const HONEYPOT_CONFIG = {
    trapClass: 'hp-trap',
    hiddenClass: 'hp-hidden',
    tokenPrefix: 'hp_',
    debug: false
};

// Генерация уникального токена
function generateTrapToken() {
    return HONEYPOT_CONFIG.tokenPrefix + Math.random().toString(36).substring(2, 10);
}

// Логирование (только в debug режиме)
function hpLog(message) {
    if (HONEYPOT_CONFIG.debug) {
        console.log('[Honeypot]', message);
    }
}

/**
 * Добавить невидимые ловушки на страницу
 */
function addHoneypotTraps() {
    hpLog('Adding honeypot traps...');
    
    // 1. Невидимое текстовое поле
    addHiddenInputTrap();
    
    // 2. Невидимая кнопка
    addHiddenButtonTrap();
    
    // 3. Ловушка для сканеров DOM
    addDOMScannerTrap();
    
    // 4. Временная ловушка
    addTimingTrap();
    
    hpLog('Honeypot traps added');
}

/**
 * Ловушка 1: Невидимое текстовое поле
 * Боты могут заполнить его, люди не видят
 */
function addHiddenInputTrap() {
    const container = document.createElement('div');
    container.style.cssText = `
        position: absolute;
        left: -9999px;
        top: -9999px;
        opacity: 0;
        visibility: hidden;
        pointer-events: none;
    `;
    
    const label = document.createElement('label');
    label.textContent = 'Leave this field empty';
    label.setAttribute('aria-hidden', 'true');
    
    const input = document.createElement('input');
    input.type = 'text';
    input.name = generateTrapToken();
    input.className = HONEYPOT_CONFIG.trapClass;
    input.setAttribute('tabindex', '-1');
    input.setAttribute('autocomplete', 'off');
    
    // Отслеживаем изменение
    input.addEventListener('change', function() {
        if (this.value) {
            triggerHoneypot('hidden_input_filled', this.value);
        }
    });
    
    input.addEventListener('input', function() {
        if (this.value) {
            triggerHoneypot('hidden_input_typing', this.value);
        }
    });
    
    container.appendChild(label);
    container.appendChild(input);
    document.body.appendChild(container);
    
    hpLog('Hidden input trap added');
}

/**
 * Ловушка 2: Невидимая кнопка
 * Боты могут нажать, люди не видят
 */
function addHiddenButtonTrap() {
    const button = document.createElement('button');
    button.type = 'button';
    button.name = generateTrapToken();
    button.className = HONEYPOT_CONFIG.trapClass;
    button.textContent = 'Click here';
    button.setAttribute('aria-hidden', 'true');
    
    // Стили для невидимости
    button.style.cssText = `
        position: absolute;
        left: -9999px;
        top: -9999px;
        opacity: 0;
        visibility: hidden;
        pointer-events: auto;  // Всё ещё кликабельна!
    `;
    
    button.addEventListener('click', function(e) {
        e.preventDefault();
        triggerHoneypot('hidden_button_clicked', this.name);
    });
    
    document.body.appendChild(button);
    
    hpLog('Hidden button trap added');
}

/**
 * Ловушка 3: Для сканеров DOM
 * Элементы, которые видны только при программном сканировании
 */
function addDOMScannerTrap() {
    // Создаём элемент с data-атрибутом, который боты могут найти
    const trapDiv = document.createElement('div');
    trapDiv.setAttribute('data-action', generateTrapToken());
    trapDiv.setAttribute('data-hp', '1');
    trapDiv.className = HONEYPOT_CONFIG.hiddenClass;
    
    // Скрываем визуально
    trapDiv.style.cssText = `
        display: none !important;
    `;
    
    // Добавляем "поддельные" команды
    const fakeCommands = [
        '/skip_verification',
        '/bypass_captcha',
        '/admin_access',
        '/unlimited_requests'
    ];
    
    fakeCommands.forEach(cmd => {
        const cmdSpan = document.createElement('span');
        cmdSpan.className = 'hp-command';
        cmdSpan.textContent = cmd;
        cmdSpan.style.display = 'none';
        trapDiv.appendChild(cmdSpan);
    });
    
    document.body.appendChild(trapDiv);
    
    // Мониторим изменения (если бот изменил display)
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes') {
                const target = mutation.target;
                if (target.style.display !== 'none') {
                    triggerHoneypot('dom_trap_exposed', trapDiv.innerHTML);
                }
            }
        });
    });
    
    observer.observe(trapDiv, { attributes: true, attributeFilter: ['style', 'class'] });
    
    hpLog('DOM scanner trap added');
}

/**
 * Ловушка 4: Временная ловушка
 * Боты реагируют слишком быстро
 */
let timingTrapActive = false;
let timingTrapToken = null;

function addTimingTrap() {
    // Создаём кнопку с задержкой активации
    const button = document.createElement('button');
    button.type = 'button';
    button.id = 'timing-trap-btn';
    button.textContent = 'Continue';
    button.disabled = true;
    button.style.cssText = `
        opacity: 0.5;
        pointer-events: none;
    `;
    
    timingTrapToken = generateTrapToken();
    button.setAttribute('data-timing-token', timingTrapToken);
    
    // Активируем через 3 секунды
    setTimeout(function() {
        button.disabled = false;
        button.style.opacity = '1';
        button.style.pointerEvents = 'auto';
        timingTrapActive = true;
        hpLog('Timing trap activated');
    }, 3000);
    
    button.addEventListener('click', function() {
        if (!timingTrapActive) {
            // Клик до активации = бот
            triggerHoneypot('timing_trap_early', 'clicked_before_activation');
        }
    });
    
    // Добавляем в конец формы или body
    const forms = document.getElementsByTagName('form');
    if (forms.length > 0) {
        forms[forms.length - 1].appendChild(button);
    } else {
        document.body.appendChild(button);
    }
    
    hpLog('Timing trap added');
}

/**
 * Триггер ловушки
 * Отправляет данные боту для обработки
 */
function triggerHoneypot(triggerType, data) {
    hpLog(`HONEYPOT TRIGGERED: ${triggerType}`);
    
    // Сохраняем информацию
    const trapData = {
        type: triggerType,
        data: data,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        url: window.location.href
    };
    
    // Отправляем боту через Telegram WebApp
    if (window.Telegram && window.Telegram.WebApp) {
        Telegram.WebApp.sendData(JSON.stringify({
            honeypot: true,
            ...trapData
        }));
    }
    
    // Также можно отправить на сервер
    // fetch('/api/honeypot/trigger', {
    //     method: 'POST',
    //     headers: {'Content-Type': 'application/json'},
    //     body: JSON.stringify(trapData)
    // });
    
    // Визуальный сигнал (только debug)
    if (HONEYPOT_CONFIG.debug) {
        alert(`🎯 HONEYPOT TRIGGERED!\nType: ${triggerType}\nBot detected!`);
    }
}

/**
 * Проверка, был ли пользователь помечен как бот
 */
function checkIfMarkedAsBot() {
    return sessionStorage.getItem('honeypot_bot') === 'true';
}

/**
 * Пометить пользователя как бота
 */
function markAsBot() {
    sessionStorage.setItem('honeypot_bot', 'true');
    
    // Показываем сообщение (опционально)
    if (HONEYPOT_CONFIG.debug) {
        alert('🤖 Bot detected! Access denied.');
    }
}

/**
 * Очистить ловушки (для SPA)
 */
function clearHoneypotTraps() {
    const traps = document.querySelectorAll('.' + HONEYPOT_CONFIG.trapClass);
    traps.forEach(trap => trap.remove());
    
    const hidden = document.querySelectorAll('.' + HONEYPOT_CONFIG.hiddenClass);
    hidden.forEach(el => el.remove());
    
    hpLog('Honeypot traps cleared');
}

// Авто-инициализация при загрузке
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addHoneypotTraps);
} else {
    addHoneypotTraps();
}

// Экспорт для использования в других скриптах
window.Honeypot = {
    addTraps: addHoneypotTraps,
    clearTraps: clearHoneypotTraps,
    trigger: triggerHoneypot,
    checkIfMarkedAsBot: checkIfMarkedAsBot,
    markAsBot: markAsBot
};
