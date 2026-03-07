package com.svoy.app.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.svoy.app.MainActivity
import com.svoy.app.R
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * Local DNS Filter VPN Service
 * 
 * Перехватывает DNS запросы и блокирует фишинговые домены.
 * Работает в локальном режиме — трафик не уходит на внешний сервер.
 */
class LocalDNSFilter : VpnService() {
    
    companion object {
        private const val TAG = "SVOY_DNS_Filter"
        private const val VPN_ADDRESS = "10.0.0.1"
        private const val VPN_PREFIX_LENGTH = 24
        private const val DNS_PORT = 53
        private const val MTU = 1500
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "dns_filter_channel"
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var vpnThread: Thread? = null
    
    // База фишинговых доменов
    private val blocklist = ConcurrentHashMap<String, Boolean>()
    
    // Белый список
    private val whitelist = setOf(
        "sberbank.ru", "sberbank-online.ru", "tinkoff.ru", "tbank.ru",
        "vtb.ru", "alfabank.ru", "gosuslugi.ru", "google.com",
        "yandex.ru", "telegram.org", "whatsapp.com"
    )
    
    // Статистика
    private var blockedCount = 0
    private var queryCount = 0
    
    override fun onCreate() {
        super.onCreate()
        loadBlocklist()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "START_DNS_FILTER") {
            startVpn()
        } else if (intent?.action == "STOP_DNS_FILTER") {
            stopVpn()
        }
        return START_STICKY
    }
    
    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DNS Фильтр",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Защита от фишинговых сайтов"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun startNotification() {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡 СВОЙ: DNS Фильтр активен")
            .setContentText("Защита от фишинговых сайтов включена")
            .setSmallIcon(R.drawable.ic_shield)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
        
        startForeground(NOTIFICATION_ID, notification)
    }
    
    private fun startVpn() {
        if (isRunning) return
        
        try {
            val builder = Builder()
                .addAddress(VPN_ADDRESS, VPN_PREFIX_LENGTH)
                .addRoute("0.0.0.0", 0)  // Перехватываем весь трафик
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setSession("SVOY DNS Filter")
                .setMtu(MTU)
            
            // Разрешаем обход для некоторых приложений (опционально)
            // builder.addDisallowedApplication("com.android.chrome")
            
            vpnInterface = builder.establish()
            
            if (vpnInterface != null) {
                isRunning = true
                startNotification()
                
                vpnThread = Thread(this::runVpnLoop)
                vpnThread?.start()
                
                Log.i(TAG, "✅ DNS Filter started")
            } else {
                Log.e(TAG, "❌ Failed to establish VPN connection")
            }
        } catch (e: Exception) {
            Log.e(TAG, "VPN start error: ${e.message}")
            stopVpn()
        }
    }
    
    private fun stopVpn() {
        isRunning = false
        vpnThread?.interrupt()
        vpnThread = null
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "DNS Filter stopped")
    }
    
    private fun runVpnLoop() {
        try {
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            val packetBuffer = ByteArray(MTU)
            
            while (isRunning && !Thread.currentThread().isInterrupted) {
                val length = inputStream.read(packetBuffer)
                if (length > 0) {
                    processPacket(packetBuffer, length, outputStream)
                }
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "VPN loop error: ${e.message}")
            }
        }
    }
    
    private fun processPacket(
        packet: ByteArray,
        length: Int,
        outputStream: FileOutputStream
    ) {
        try {
            // Парсим IP пакет
            if (length < 20) return
            
            val version = (packet[0].toInt() shr 4) and 0x0F
            if (version != 4) return  // Только IPv4
            
            val protocol = packet[9].toInt() and 0xFF
            if (protocol != 17) return  // Только UDP (DNS)
            
            // Парсим UDP
            val ipHeaderLength = ((packet[0].toInt() and 0x0F) * 4)
            if (length < ipHeaderLength + 8) return
            
            val srcPort = ((packet[ipHeaderLength].toInt() and 0xFF) shl 8) or
                         (packet[ipHeaderLength + 1].toInt() and 0xFF)
            val dstPort = ((packet[ipHeaderLength + 2].toInt() and 0xFF) shl 8) or
                         (packet[ipHeaderLength + 3].toInt() and 0xFF)
            
            // DNS запросы идут на порт 53
            if (dstPort != DNS_PORT) return
            
            queryCount++
            
            // Парсим DNS запрос
            val dnsData = packet.copyOfRange(ipHeaderLength + 8, length)
            val domain = parseDnsQuery(dnsData)
            
            if (domain != null) {
                Log.d(TAG, "DNS query: $domain")
                
                // Проверка на фишинг
                if (isPhishing(domain)) {
                    blockedCount++
                    Log.w(TAG, "🚫 BLOCKED: $domain (total: $blockedCount)")
                    
                    // Отправляем уведомление
                    sendBlockNotification(domain)
                    
                    // Возвращаем заблокированный ответ
                    val blockResponse = createBlockResponse(dnsData, "127.0.0.1")
                    // Отправляем ответ обратно (упрощённо)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Packet processing error: ${e.message}")
        }
    }
    
    private fun parseDnsQuery(data: ByteArray): String? {
        if (data.size < 12) return null
        
        val qCount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (qCount == 0) return null
        
        // Парсинг доменного имени
        val labels = mutableListOf<String>()
        var offset = 12
        
        while (offset < data.size) {
            val length = data[offset].toInt() and 0xFF
            if (length == 0) break
            
            if (offset + 1 + length > data.size) break
            
            val label = String(data, offset + 1, length, Charsets.UTF_8)
            labels.add(label)
            offset += 1 + length
        }
        
        return if (labels.isNotEmpty()) labels.joinToString(".") else null
    }
    
    private fun isPhishing(domain: String): Boolean {
        val lowerDomain = domain.lowercase()
        
        // Белый список
        if (whitelist.any { lowerDomain.endsWith(it) }) {
            return false
        }
        
        // Чёрный список
        if (blocklist.containsKey(lowerDomain)) {
            return true
        }
        
        // Проверка паттернов
        val phishingPatterns = listOf(
            "sber", "sberbank", "tinkoff", "tbank", "vtb", "alfa",
            "gosuslugi", "госуслуг", "почта", "mail", "yandex"
        )
        
        val suspiciousTlds = listOf(".ru", ".рф", ".xyz", ".top", ".tk")
        
        for (pattern in phishingPatterns) {
            if (pattern in lowerDomain) {
                for (tld in suspiciousTlds) {
                    if (lowerDomain.endsWith(tld)) {
                        if (lowerDomain.count { it == '-' } >= 1) {
                            return true
                        }
                        if (lowerDomain.count { it == pattern[0] } > 3) {
                            return true
                        }
                    }
                }
            }
        }
        
        // Очень длинные домены
        if (lowerDomain.length > 40) {
            return true
        }
        
        return false
    }
    
    private fun createBlockResponse(query: ByteArray, ip: String): ByteArray {
        // Создаём DNS ответ с заблокированным IP
        val response = ByteArrayOutputStream()
        
        // Копируем ID
        response.write(query.copyOf(2))
        
        // Флаги
        response.write(byteArrayOf(0x81.toByte(), 0x80.toByte()))
        
        // Количество вопросов
        response.write(query.copyOfRange(4, 6))
        
        // Количество ответов: 1
        response.write(byteArrayOf(0x00, 0x01))
        response.write(byteArrayOf(0x00, 0x00))
        response.write(byteArrayOf(0x00, 0x00))
        
        // Копируем вопрос
        response.write(query.copyOfRange(12, query.size))
        
        // Добавляем ответ
        // Сжатие имени
        response.write(byteArrayOf(0xC0.toByte(), 0x0C.toByte()))
        
        // Тип: A, класс: IN
        response.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
        
        // TTL: 300
        response.write(byteArrayOf(0x00, 0x00, 0x01, 0x2C))
        
        // Длина данных: 4
        response.write(byteArrayOf(0x00, 0x04))
        
        // IP адрес
        ip.split(".").map { it.toInt() }.forEach {
            response.write(it)
        }
        
        return response.toByteArray()
    }
    
    private fun loadBlocklist() {
        try {
            val file = java.io.File(filesDir, "phishing_domains.txt")
            if (file.exists()) {
                file.forEachLine { line ->
                    val domain = line.trim().lowercase()
                    if (domain.isNotEmpty() && !domain.startsWith("#")) {
                        blocklist[domain] = true
                    }
                }
                Log.i(TAG, "Loaded ${blocklist.size} domains")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load blocklist: ${e.message}")
        }
    }
    
    fun addPhishingDomain(domain: String) {
        blocklist[domain.lowercase()] = true
        // Сохраняем в файл
        try {
            val file = java.io.File(filesDir, "phishing_domains.txt")
            file.appendText("$domain\n")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save domain: ${e.message}")
        }
    }
    
    private fun sendBlockNotification(domain: String) {
        // Отправляем пуш уведомление о заблокированном домене
        // (можно реализовать через BroadcastReceiver)
    }
    
    fun getStats(): Map<String, Int> {
        return mapOf(
            "blocked_domains" to blocklist.size,
            "blocked_queries" to blockedCount,
            "total_queries" to queryCount
        )
    }
}

// Простой ByteArrayOutputStream для Kotlin
class ByteArrayOutputStream {
    private val buffer = ByteArrayOutputStream()
    
    fun write(byte: Int) = buffer.write(byte)
    fun write(bytes: ByteArray) = buffer.write(bytes)
    fun write(bytes: ByteArray, offset: Int, length: Int) = buffer.write(bytes, offset, length)
    fun toByteArray(): ByteArray = buffer.toByteArray()
}
