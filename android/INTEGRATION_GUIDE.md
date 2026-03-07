# 🛡 ИНТЕГРАЦИЯ ЗАЩИТЫ "НУЛЕВОГО ИНЦИДЕНТА" В ANDROID

## УРОВЕНЬ 1: DNS ФИЛЬТР

### 1.1 Добавить разрешения в AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```

### 1.2 Добавить сервисы

```xml
<service
    android:name=".services.LocalDNSFilter"
    android:permission="android.permission.BIND_VPN_SERVICE"
    android:exported="false">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>

<service
    android:name=".services.BankShieldService"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
    android:exported="false">
    <intent-filter>
        <action android:name="android.accessibilityservice.AccessibilityService" />
    </intent-filter>
    <meta-data
        android:name="android.accessibilityservice"
        android:resource="@xml/accessibility_config" />
</service>
```

### 1.3 Использование в MainActivity

```kotlin
class MainActivity : AppCompatActivity() {
    
    private lateinit var dnsManager: DnsFilterManager
    private lateinit var bankShield: BankShieldManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Инициализация
        dnsManager = DnsFilterManager(this)
        bankShield = BankShieldManager(this)
        
        // Запрос разрешения на VPN
        requestVpnPermission()
        
        // Запуск защиты
        startProtection()
    }
    
    private fun requestVpnPermission() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            // Разрешение уже есть
            dnsManager.start()
        }
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            dnsManager.start()
        }
    }
    
    private fun startProtection() {
        // DNS Фильтр
        dnsManager.loadBlocklist()
        dnsManager.start()
        
        // Bank Shield
        bankShield.requestAccessibility()
        
        // Clipboard Sentinel
        ClipboardMonitor.start(this)
    }
    
    companion object {
        private const val VPN_REQUEST_CODE = 1001
    }
}
```

### 1.4 Мониторинг статуса (Jetpack Compose)

```kotlin
@Composable
fun ProtectionStatusCard() {
    val dnsManager = remember { DnsFilterManager(LocalContext.current) }
    val status by dnsManager.status.collectAsState()
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (status) {
                DnsFilterManager.STATUS_RUNNING -> Color.Green
                DnsFilterManager.STATUS_ERROR -> Color.Red
                else -> Color.Gray
            }
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = when (status) {
                    DnsFilterManager.STATUS_RUNNING -> "🛡 Защита активна"
                    DnsFilterManager.STATUS_STOPPED -> "⚪️ Защита отключена"
                    DnsFilterManager.STATUS_ERROR -> "❌ Ошибка защиты"
                    else -> "⏳ Запуск..."
                },
                style = MaterialTheme.typography.titleMedium
            )
            
            // Статистика
            val stats by dnsManager.stats.collectAsState()
            Text("Заблокировано: ${stats["blocked_domains"]}")
            Text("Запросов: ${stats["total_queries"]}")
        }
    }
}
```

---

## УРОВЕНЬ 2: BANK SHIELD

### 2.1 accessibility_config.xml

Создать `res/xml/accessibility_config.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<accessibility-service xmlns:android="http://schemas.android.com/apk/res/android"
    android:accessibilityEventTypes="typeWindowStateChanged|typeWindowContentChanged"
    android:accessibilityFeedbackType="feedbackVisual"
    android:accessibilityFlags="flagDefault|flagIncludeNotImportantViews|flagReportViewIds"
    android:canRetrieveWindowContent="true"
    android:notificationTimeout="100"
    android:description="@string/bank_shield_description"
    android:settingsActivity="com.svoy.app.settings.SettingsActivity" />
```

### 2.2 Запрос доступа

```kotlin
class BankShieldManager(private val context: Context) {
    
    fun requestAccessibility() {
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }
    
    fun isEnabled(): Boolean {
        val serviceName = ComponentName(
            context,
            BankShieldService::class.java
        )
        
        val enabled = AccessibilityManager::class.java
            .cast(context.getSystemService(Context.ACCESSIBILITY_SERVICE))
            ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            ?.any { it.resolveInfo.serviceInfo.packageName == serviceName.packageName }
            ?: false
        
        return enabled
    }
}
```

---

## УРОВЕНЬ 3: CLIPBOARD SENTINEL

### 3.1 Запуск фонового мониторинга

```kotlin
class ClipboardMonitor {
    
    companion object {
        fun start(context: Context) {
            val intent = Intent(context, ClipboardService::class.java)
            context.startForegroundService(intent)
        }
        
        fun stop(context: Context) {
            val intent = Intent(context, ClipboardService::class.java)
            context.stopService(intent)
        }
    }
}
```

### 3.2 Обработка检测结果

```kotlin
class ClipboardService : Service() {
    
    private lateinit var clipboardManager: ClipboardManager
    private var lastClipboardText: String = ""
    
    override fun onCreate() {
        super.onCreate()
        
        clipboardManager = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        
        // Мониторинг буфера
        val primaryClipChangedListener = ClipboardManager.OnPrimaryClipChangedListener {
            checkClipboard()
        }
        
        clipboardManager.addPrimaryClipChangedListener(primaryClipChangedListener)
    }
    
    private fun checkClipboard() {
        val clip = clipboardManager.primaryClip
        if (clip == null || clip.itemCount == 0) return
        
        val text = clip.getItemAt(0).text?.toString() ?: return
        if (text == lastClipboardText) return
        
        lastClipboardText = text
        
        // Проверка на фишинг
        if (isPhishingLink(text)) {
            showWarningNotification(text)
        }
    }
    
    private fun isPhishingLink(text: String): Boolean {
        // Проверка URL
        val urlPattern = Pattern.compile(
            "https?://([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}(/[^\\s]*)?"
        )
        
        val matcher = urlPattern.matcher(text)
        if (!matcher.find()) return false
        
        val url = matcher.group()
        
        // Проверка на фишинговые паттерны
        val phishingPatterns = listOf(
            "sber", "sberbank", "tinkoff", "tbank", "vtb",
            "gosuslugi", "госуслуг"
        )
        
        val suspiciousTlds = listOf(".xyz", ".top", ".tk", ".ml")
        
        for (pattern in phishingPatterns) {
            if (pattern in url) {
                for (tld in suspiciousTlds) {
                    if (url.endsWith(tld)) return true
                }
            }
        }
        
        return false
    }
    
    private fun showWarningNotification(text: String) {
        val notification = NotificationCompat.Builder(this, "clipboard_channel")
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("⚠️ Опасная ссылка!")
            .setContentText("Не переходите по этой ссылке — это может быть фишинг")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_SECURITY)
            .build()
        
        NotificationManagerCompat.from(this)
            .notify(1001, notification)
    }
}
```

---

## 📊 СТАТИСТИКА И МОНИТОРИНГ

### Dashboard в приложении

```kotlin
@Composable
fun SecurityDashboard() {
    val context = LocalContext.current
    val dnsManager = remember { DnsFilterManager(context) }
    
    val dnsStatus by dnsManager.status.collectAsState()
    val dnsStats by dnsManager.stats.collectAsState()
    
    Column {
        // DNS Статус
        StatusCard(
            title = "DNS Фильтр",
            status = dnsStatus,
            stats = dnsStats
        )
        
        // Bank Shield Статус
        BankShieldStatus()
        
        // Clipboard Статус
        ClipboardStatus()
    }
}
```

---

## ✅ ЧЕКЛИСТ ИНТЕГРАЦИИ

- [ ] Добавить разрешения в AndroidManifest.xml
- [ ] Добавить сервисы (DNS, Bank Shield, Clipboard)
- [ ] Создать accessibility_config.xml
- [ ] Реализовать запрос разрешений
- [ ] Добавить UI для управления защитой
- [ ] Реализовать мониторинг статуса
- [ ] Добавить уведомления о угрозах
- [ ] Протестировать на реальных устройствах

---

**Версия:** 1.0  
**Дата:** 2026-03-06
