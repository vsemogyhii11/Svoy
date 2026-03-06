/**
 * Advanced Device Fingerprinting
 * 
 * Собирает уникальные отпечатки устройства через:
 * - Canvas fingerprinting
 * - WebRTC leak (реальный IP даже с VPN)
 * - AudioContext fingerprinting
 * - WebGL fingerprinting
 * - Screen/Touch анализ
 * 
 * Использование в WebApp:
 *   const fp = await getAdvancedFingerprint();
 *   Telegram.WebApp.sendData(JSON.stringify(fp));
 */

// Конфигурация
const FP_CONFIG = {
    debug: false,
    cacheTTL: 3600000, // 1 час
    sendToBot: true
};

// Логирование
function fpLog(message) {
    if (FP_CONFIG.debug) {
        console.log('[Fingerprint]', message);
    }
}

/**
 * Canvas Fingerprinting
 * Рендерит скрытый canvas и хэширует результат
 */
async function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        canvas.style.display = 'none';
        
        const ctx = canvas.getContext('2d');
        
        // Рендеринг текста с антиалиасингом
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(0, 0, 100, 50);
        ctx.fillStyle = '#069';
        ctx.fillText('Fingerprint Test 🎨', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Fingerprint Test 🎨', 4, 27);
        
        document.body.appendChild(canvas);
        
        // Получаем data URL и хэшируем
        const dataURL = canvas.toDataURL();
        const hash = await simpleHash(dataURL);
        
        document.body.removeChild(canvas);
        
        fpLog(`Canvas fingerprint: ${hash}`);
        return hash;
    } catch (e) {
        fpLog(`Canvas fingerprint error: ${e}`);
        return 'canvas_unavailable';
    }
}

/**
 * WebRTC Leak Detection
 * Получает реальный IP даже через VPN
 */
async function getWebRTCIPs() {
    const ips = [];
    
    try {
        const peerConnection = new (window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection)({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        
        peerConnection.createDataChannel('');
        
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        
        // Ждём ICE кандидаты
        await new Promise((resolve) => {
            let checkCount = 0;
            const checkInterval = setInterval(() => {
                if (peerConnection.localDescription) {
                    const lines = peerConnection.localDescription.sdp.split('\n');
                    
                    for (const line of lines) {
                        if (line.includes('a=candidate:') && line.includes('udp')) {
                            const parts = line.split(' ');
                            const ip = parts.find(p => p.match(/\d+\.\d+\.\d+\.\d+/));
                            if (ip && !ips.includes(ip)) {
                                ips.push(ip);
                            }
                        }
                    }
                    
                    if (ips.length > 0 || checkCount > 10) {
                        clearInterval(checkInterval);
                        resolve();
                    }
                    checkCount++;
                }
            }, 100);
            
            setTimeout(resolve, 5000); // Таймаут 5 сек
        });
        
        peerConnection.close();
        
        fpLog(`WebRTC IPs found: ${ips.length}`);
        return ips;
    } catch (e) {
        fpLog(`WebRTC error: ${e}`);
        return [];
    }
}

/**
 * AudioContext Fingerprinting
 * Уникальные характеристики аудио обработки
 */
async function getAudioFingerprint() {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const analyser = audioCtx.createAnalyser();
        const gain = audioCtx.createGain();
        const compressor = audioCtx.createDynamicsCompressor();
        
        oscillator.type = 'triangle';
        oscillator.frequency.value = 1000;
        
        analyser.fftSize = 256;
        gain.gain.value = 0.1;
        
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0.003;
        compressor.release.value = 0.25;
        
        oscillator.connect(analyser);
        analyser.connect(compressor);
        compressor.connect(gain);
        gain.connect(audioCtx.destination);
        
        oscillator.start(0);
        
        // Ждём стабилизации
        await new Promise(resolve => setTimeout(resolve, 100));
        
        const buffer = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(buffer);
        
        // Хэшируем результат
        const data = Array.from(buffer).join(',');
        const hash = await simpleHash(data);
        
        oscillator.stop();
        audioCtx.close();
        
        fpLog(`Audio fingerprint: ${hash}`);
        return hash;
    } catch (e) {
        fpLog(`Audio fingerprint error: ${e}`);
        return 'audio_unavailable';
    }
}

/**
 * WebGL Fingerprinting
 * Информация о GPU и рендерере
 */
function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        
        if (!gl) {
            return 'webgl_unavailable';
        }
        
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        
        const fingerprint = {
            vendor: gl.getParameter(gl.VENDOR),
            renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown',
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
            aliasedLineWidthRange: gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE),
            aliasedPointSizeRange: gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)
        };
        
        fpLog(`WebGL fingerprint: ${JSON.stringify(fingerprint)}`);
        return fingerprint;
    } catch (e) {
        fpLog(`WebGL error: ${e}`);
        return 'webgl_error';
    }
}

/**
 * Screen & Touch Analysis
 */
function getScreenFingerprint() {
    const screen = {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        devicePixelRatio: window.devicePixelRatio,
        orientation: screen.orientation ? screen.orientation.type : 'unknown',
        touchPoints: 'ontouchstart' in window ? ('maxTouchPoints' in navigator ? navigator.maxTouchPoints : 0) : 0
    };
    
    // Вычисляем hash
    const screenString = Object.values(screen).join('|');
    const hash = simpleHashSync(screenString);
    
    return {
        ...screen,
        hash: hash.toString(16)
    };
}

/**
 * Browser & System Info
 */
function getBrowserFingerprint() {
    return {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? navigator.languages.join(',') : navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
        deviceMemory: navigator.deviceMemory || 'unknown',
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack || 'unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        pdfViewerEnabled: navigator.pdfViewerEnabled ? 'yes' : 'no'
    };
}

/**
 * Fonts Detection (базовое)
 */
async function getFontsFingerprint() {
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testFonts = [
        'Arial', 'Times New Roman', 'Courier New', 'Verdana',
        'Georgia', 'Palatino', 'Garamond', 'Bookman',
        'Comic Sans MS', 'Trebuchet MS', 'Arial Black', 'Impact'
    ];
    
    const detected = [];
    
    // Создаём скрытый элемент для теста
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.font = '72px monospace';
    const baseWidth = ctx.measureText('mmmmmmmmmmlli').width;
    
    for (const font of testFonts) {
        ctx.font = `72px "${font}", ${baseFonts[0]}`;
        const width = ctx.measureText('mmmmmmmmmmlli').width;
        
        if (width !== baseWidth) {
            detected.push(font);
        }
    }
    
    const hash = await simpleHash(detected.join(','));
    
    return {
        fonts: detected,
        count: detected.length,
        hash: hash
    };
}

/**
 * Простая хэш-функция (для строк)
 */
async function simpleHash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    
    // Используем SubtleCrypto если доступен
    if (crypto.subtle) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
    }
    
    // Fallback
    return simpleHashSync(str).toString(16);
}

function simpleHashSync(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash);
}

/**
 * Основная функция сбора fingerprint
 */
async function getAdvancedFingerprint() {
    fpLog('Starting advanced fingerprint collection...');
    
    const startTime = performance.now();
    
    // Параллельный сбор данных
    const [
        canvas,
        webrtcIPs,
        audio,
        webgl,
        screen,
        browser,
        fonts
    ] = await Promise.all([
        getCanvasFingerprint(),
        getWebRTCIPs(),
        getAudioFingerprint(),
        getWebGLFingerprint(),
        Promise.resolve(getScreenFingerprint()),
        Promise.resolve(getBrowserFingerprint()),
        getFontsFingerprint()
    ]);
    
    // Комбинируем в общий fingerprint
    const fingerprint = {
        // Основные идентификаторы
        canvas_hash: canvas,
        audio_hash: audio,
        screen_hash: screen.hash,
        fonts_hash: fonts.hash,
        
        // Детали
        webrtc_ips: webrtcIPs,
        real_ip: webrtcIPs[0] || null,
        webgl_info: webgl,
        screen_info: screen,
        browser_info: browser,
        fonts_info: fonts,
        
        // Мета
        collected_at: new Date().toISOString(),
        collection_time_ms: Math.round(performance.now() - startTime)
    };
    
    // Генерируем общий hash
    const combinedString = [
        fingerprint.canvas_hash,
        fingerprint.audio_hash,
        fingerprint.screen_hash,
        fingerprint.fonts_hash,
        fingerprint.real_ip,
        fingerprint.browser_info.userAgent
    ].join('|');
    
    fingerprint.device_hash = await simpleHash(combinedString);
    
    fpLog(`Advanced fingerprint collected in ${fingerprint.collection_time_ms}ms`);
    fpLog(`Device hash: ${fingerprint.device_hash}`);
    
    // Отправка боту если настроено
    if (FP_CONFIG.sendToBot && window.Telegram && window.Telegram.WebApp) {
        Telegram.WebApp.sendData(JSON.stringify({
            type: 'advanced_fingerprint',
            ...fingerprint
        }));
    }
    
    return fingerprint;
}

/**
 * Проверка на эмуляцию/VM
 */
function detectEmulation() {
    const indicators = [];
    
    // WebDriver (автоматизация)
    if (navigator.webdriver) {
        indicators.push('webdriver_detected');
    }
    
    // Headless Chrome
    if (navigator.plugins.length === 0) {
        indicators.push('no_plugins');
    }
    
    // Несоответствие platform и userAgent
    const isMobile = /Mobile|Android|iPhone/i.test(navigator.userAgent);
    const isDesktop = !isMobile;
    
    if (isDesktop && navigator.platform === 'Linux x86_64') {
        // Может быть VM
        if (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2) {
            indicators.push('low_cpu_cores');
        }
        if (navigator.deviceMemory && navigator.deviceMemory <= 2) {
            indicators.push('low_memory');
        }
    }
    
    // Touch points несоответствие
    if (navigator.maxTouchPoints > 0 && !isMobile) {
        indicators.push('touch_on_desktop');
    }
    
    return {
        is_suspicious: indicators.length > 0,
        indicators: indicators,
        count: indicators.length
    };
}

/**
 * Экспорт функций
 */
window.AdvancedFingerprint = {
    getFingerprint: getAdvancedFingerprint,
    getCanvasFingerprint,
    getWebRTCIPs,
    getAudioFingerprint,
    getWebGLFingerprint,
    getScreenFingerprint,
    getBrowserFingerprint,
    getFontsFingerprint,
    detectEmulation,
    simpleHash
};

// Авто-сбор при загрузке (опционально)
if (FP_CONFIG.debug) {
    getAdvancedFingerprint().then(fp => {
        console.log('Auto-collected fingerprint:', fp);
    });
}
