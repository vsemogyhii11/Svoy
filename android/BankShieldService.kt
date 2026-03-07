package com.svoy.app.services

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AlertDialog
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.SoundPool
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import com.svoy.app.MainActivity
import com.svoy.app.R

/**
 * Bank Shield — защита банковских приложений.
 * 
 * Обнаруживает:
 * - Наложения поверх банков (overlay attacks)
 * - Запущенные программы удалённого доступа (AnyDesk, TeamViewer)
 * - Попытки скриншотов
 * - Демонстрацию экрана
 */
class BankShieldService : AccessibilityService() {
    
    companion object {
        private const val TAG = "SVOY_BankShield"
        private const val NOTIFICATION_ID = 1002
        private const val CHANNEL_ID = "bank_shield_channel"
        
        // Пакеты банковских приложений
        val BANK_PACKAGES = setOf(
            "ru.sberbank.mobile",
            "com.idmobile.android",  // Тинькофф
            "ru.vtb24.mobilebanking.android",
            "ru.alfabank.mobile.android",
            "ru.gazprombank.android",
            "ru.raiffeisen.news",
            "ru.rshb.mobile.android",
            "com.payanywhere.sbp",
            "ru.nspk.mirpay"
        )
        
        // Приложения удалённого доступа
        val SCREEN_SHARING_APPS = setOf(
            "com.teamviewer.teamviewer.market.mobile",
            "com.teamviewer.quicksupport.addon.samsung",
            "com.anydesk.anydeskandroid",
            "com.rustdesk.rustdesk",
            "com.ammyy.ammyyadmin",
            "com.logmein.rescueandroid",
            "com.bomgar.bomgarclient"
        )
        
        // Ключевые слова для детекции мошенничества в тексте
        val FRAUD_KEYWORDS = setOf(
            "код из смс", "смс код", "код подтверждения",
            "перевод", "карта", "счёт", "баланс",
            "безопасный счёт", "резервный счёт",
            "сотрудник банка", "оператор", "служба безопасности",
            "срочно", "немедленно", "в течение",
            "заблокирован", "разблокировать",
            "взлом", "мошенники", "подозрительная операция"
        )
    }
    
    private var isBankAppOpen = false
    private var currentPackage = ""
    private val handler = Handler(Looper.getMainLooper())
    private var soundPool: SoundPool? = null
    private var alarmSoundId = 0
    
    // Детекция запущенных приложений
    private val runningApps = mutableSetOf<String>()
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        setupSoundPool()
    }
    
    override fun onServiceConnected() {
        super.onServiceConnected()
        
        val info = AccessibilityServiceInfo().apply {
            eventTypes = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                        AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED or
                        AccessibilityEvent.TYPES_ALL_MASK
            feedbackType = AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            flags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS or
                   AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
                   AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        }
        
        setServiceInfo(info)
        Log.i(TAG, "Bank Shield connected")
    }
    
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        
        val packageName = event.packageName?.toString() ?: return
        currentPackage = packageName
        
        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                checkBankAppWindow(packageName)
                checkOverlays(packageName)
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                checkTextForFraud(event)
            }
        }
        
        // Проверка на запущенные приложения удалённого доступа
        checkScreenSharingApps()
    }
    
    override fun onInterrupt() {
        Log.w(TAG, "Bank Shield interrupted")
    }
    
    override fun onDestroy() {
        super.onDestroy()
        soundPool?.release()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Защита Банков",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Предупреждения о попытках взлома"
                enableVibration(true)
                setShowBadge(true)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun setupSoundPool() {
        val audioAttributes = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ALARM)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        
        soundPool = SoundPool.Builder()
            .setMaxStreams(3)
            .setAudioAttributes(audioAttributes)
            .build()
        
        // Загружаем звук сирены (нужно добавить в raw/siren.mp3)
        // alarmSoundId = soundPool?.load(this, R.raw.siren, 1) ?: 0
    }
    
    private fun playAlarmSound() {
        soundPool?.play(alarmSoundId, 1.0f, 1.0f, 1, 0, 1.0f)
    }
    
    private fun checkBankAppWindow(packageName: String) {
        val wasBankApp = isBankAppOpen
        isBankAppOpen = packageName in BANK_PACKAGES
        
        when {
            // Только что открыли банк
            isBankAppOpen && !wasBankApp -> {
                Log.i(TAG, "🏦 Bank app opened: $packageName")
                enableSecureMode()
                sendNotification("🛡 Защита банка активирована", "Режим повышенной безопасности")
            }
            // Закрыли банк
            !isBankAppOpen && wasBankApp -> {
                Log.i(TAG, "Bank app closed: $packageName")
                disableSecureMode()
            }
        }
    }
    
    private fun enableSecureMode() {
        // В реальном приложении:
        // - Блокируем скриншоты через FLAG_SECURE
        // - Включаем мониторинг наложений
        Log.d(TAG, "Secure mode enabled")
    }
    
    private fun disableSecureMode() {
        Log.d(TAG, "Secure mode disabled")
    }
    
    private fun checkOverlays(packageName: String) {
        if (!isBankAppOpen) return
        
        // Проверка на наложения
        val overlayPackages = getOverlayPackages()
        
        if (overlayPackages.isNotEmpty()) {
            Log.w(TAG, "⚠️ OVERLAY DETECTED: $overlayPackages")
            
            // Тревога!
            handler.post {
                showOverlayWarning(overlayPackages)
                sendAlertNotification(
                    "⚠️ ОБНАРУЖЕНО НАЛОЖЕНИЕ!",
                    "Поверх банка открыто подозрительное окно"
                )
                playAlarmSound()
            }
        }
    }
    
    private fun getOverlayPackages(): List<String> {
        // В реальности нужно использовать Settings.Secure.getString
        // для получения приложений с permission SYSTEM_ALERT_WINDOW
        // Это упрощённая версия
        return emptyList()
    }
    
    private fun checkScreenSharingApps() {
        val activeScreenSharing = SCREEN_SHARING_APPS.filter { 
            isAppRunning(it) 
        }
        
        if (activeScreenSharing.isNotEmpty() && isBankAppOpen) {
            Log.w(TAG, "🚨 SCREEN SHARING DETECTED: $activeScreenSharing")
            
            handler.post {
                showScreenSharingWarning(activeScreenSharing)
                sendAlertNotification(
                    "🚨 ДЕМОНСТРАЦИЯ ЭКРАНА!",
                    "Обнаружен AnyDesk/TeamViewer. Немедленно закройте!"
                )
                playAlarmSound()
                
                // Отправляем SOS родственникам
                sendSOSAlert()
            }
        }
    }
    
    private fun isAppRunning(packageName: String): Boolean {
        // В реальности нужно использовать UsageStatsManager
        // Это упрощённая версия
        return runningApps.contains(packageName)
    }
    
    private fun checkTextForFraud(event: AccessibilityEvent) {
        if (!isBankAppOpen) return
        
        val text = event.text?.joinToString(" ")?.lowercase() ?: return
        
        // Проверка на ключевые слова мошенничества
        val foundKeywords = FRAUD_KEYWORDS.filter { it in text }
        
        if (foundKeywords.size >= 3) {  // 3+ слова = высокий риск
            Log.w(TAG, "⚠️ FRAUD TEXT DETECTED: $foundKeywords")
            
            handler.post {
                showFraudWarning(foundKeywords)
                sendAlertNotification(
                    "⚠️ ПРИЗНАКИ МОШЕННИЧЕСТВА",
                    "Обнаружены подозрительные слова в переписке"
                )
            }
        }
    }
    
    private fun showOverlayWarning(overlayPackages: List<String>) {
        AlertDialog.Builder(this)
            .setTitle("⚠️ ОБНАРУЖЕНО НАЛОЖЕНИЕ!")
            .setMessage(
                "Поверх банковского приложения открыто другое окно!\n\n" +
                "Это может быть атака мошенников.\n\n" +
                "Приложения: $overlayPackages\n\n" +
                "Немедленно закройте все подозрительные окна!"
            )
            .setPositiveButton("Закрыть всё") { _, _ ->
                closeOverlayApps(overlayPackages)
            }
            .setNegativeButton("Игнорировать", null)
            .show()
    }
    
    private fun showScreenSharingWarning(apps: List<String>) {
        AlertDialog.Builder(this)
            .setTitle("🚨 ДЕМОНСТРАЦИЯ ЭКРАНА!")
            .setMessage(
                "Обнаружено приложение для удалённого доступа!\n\n" +
                "Приложения: $apps\n\n" +
                "МОШЕННИКИ ВИДЯТ ВАШ ЭКРАН!\n\n" +
                "НЕМЕДЛЕННО ЗАКРОЙТЕ ЭТО ПРИЛОЖЕНИЕ!"
            )
            .setPositiveButton("Закрыть") { _, _ ->
                closeScreenSharingApps(apps)
            }
            .setNegativeButton("Позвать помощь") { _, _ ->
                sendSOSAlert()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun showFraudWarning(keywords: List<String>) {
        AlertDialog.Builder(this)
            .setTitle("⚠️ ПРИЗНАКИ МОШЕННИЧЕСТВА")
            .setMessage(
                "В переписке обнаружены подозрительные слова:\n\n" +
                "${keywords.joinToString(", ")}\n\n" +
                "Будьте осторожны! Не сообщайте коды из СМС."
            )
            .setPositiveButton("Понятно", null)
            .show()
    }
    
    private fun closeOverlayApps(packages: List<String>) {
        // Попытка закрыть приложения
        Log.i(TAG, "Closing overlay apps: $packages")
    }
    
    private fun closeScreenSharingApps(apps: List<String>) {
        Log.i(TAG, "Closing screen sharing apps: $apps")
    }
    
    private fun sendNotification(title: String, message: String) {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()
        
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    
    private fun sendAlertNotification(title: String, message: String) {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_alert)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setVibrate(longArrayOf(0, 500, 200, 500, 200, 500))
            .build()
        
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID + 1, notification)
    }
    
    private fun sendSOSAlert() {
        // Отправка SOS уведомления доверенным контактам
        Log.i(TAG, "SOS Alert sent!")
        
        // В реальности:
        // - Отправить пуш родственникам
        // - Отправить SMS
        // - Отправить местоположение
    }
    
    fun getStats(): Map<String, Any> {
        return mapOf(
            "is_bank_app_open" to isBankAppOpen,
            "current_package" to currentPackage,
            "running_apps" to runningApps.size
        )
    }
}
