package com.svoy.app.services

import android.content.Context
import android.content.Intent
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * Менеджер DNS Фильтра
 * 
 * Управление VPN сервисом для блокировки фишинговых доменов.
 */
class DnsFilterManager(private val context: Context) {
    
    companion object {
        private const val TAG = "SVOY_DNS_Manager"
        
        // Статусы
        const val STATUS_STOPPED = 0
        const val STATUS_STARTING = 1
        const val STATUS_RUNNING = 2
        const val STATUS_ERROR = 3
    }
    
    // Состояние сервиса
    private val _status = MutableStateFlow(STATUS_STOPPED)
    val status: StateFlow<Int> = _status.asStateFlow()
    
    // Статистика
    private val _stats = MutableStateFlow(mapOf(
        "blocked_domains" to 0,
        "total_queries" to 0,
        "uptime_seconds" to 0
    ))
    val stats: StateFlow<Map<String, Int>> = _stats.asStateFlow()
    
    /**
     * Запустить DNS фильтр
     */
    fun start() {
        if (_status.value == STATUS_RUNNING) {
            Log.w(TAG, "DNS Filter already running")
            return
        }
        
        try {
            _status.value = STATUS_STARTING
            
            val intent = Intent(context, LocalDNSFilter::class.java)
            intent.action = "START_DNS_FILTER"
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            
            _status.value = STATUS_RUNNING
            Log.i(TAG, "✅ DNS Filter started")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start DNS Filter", e)
            _status.value = STATUS_ERROR
        }
    }
    
    /**
     * Остановить DNS фильтр
     */
    fun stop() {
        if (_status.value != STATUS_RUNNING) {
            return
        }
        
        try {
            val intent = Intent(context, LocalDNSFilter::class.java)
            intent.action = "STOP_DNS_FILTER"
            context.stopService(intent)
            
            _status.value = STATUS_STOPPED
            Log.i(TAG, "DNS Filter stopped")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop DNS Filter", e)
        }
    }
    
    /**
     * Добавить фишинговый домен в блок-лист
     */
    fun addPhishingDomain(domain: String) {
        val file = File(context.filesDir, "phishing_domains.txt")
        file.appendText("$domain\n")
        
        // Уведомить сервис об обновлении
        val intent = Intent(context, LocalDNSFilter::class.java)
        intent.action = "RELOAD_BLOCKLIST"
        context.startService(intent)
        
        Log.i(TAG, "Added phishing domain: $domain")
    }
    
    /**
     * Загрузить блок-лист из файла
     */
    fun loadBlocklist(): Int {
        val file = File(context.filesDir, "phishing_domains.txt")
        if (!file.exists()) {
            // Создать дефолтный блок-лист
            createDefaultBlocklist()
        }
        
        val count = file.readLines().count { it.isNotBlank() && !it.startsWith("#") }
        Log.i(TAG, "Loaded $count phishing domains")
        
        return count
    }
    
    /**
     * Создать дефолтный блок-лист
     */
    private fun createDefaultBlocklist() {
        val file = File(context.filesDir, "phishing_domains.txt")
        
        val defaultDomains = listOf(
            // Фишинг Сбербанк
            "sber-bank.ru",
            "sberbank-online-verify.ru",
            "sberbank-security.ru",
            "sberr-bank.ru",
            
            // Фишинг Тинькофф
            "tinkoff-verify.ru",
            "tbank-security.ru",
            "tinkoff-auth.ru",
            
            // Фишинг ВТБ
            "vtb-secure.ru",
            "vtb24-online.ru",
            
            // Фишинг Госуслуги
            "gosuslugi-verify.ru",
            "gosuslugi-auth.ru",
            "госуслуги-подтверждение.рф",
            
            // Общие фишинговые паттерны
            "secure-bank-verify.ru",
            "account-confirmation.ru",
            "verify-identity.ru"
        )
        
        file.writeText("# Фишинговые домены (автогенерация)\n")
        defaultDomains.forEach { domain ->
            file.appendText("$domain\n")
        }
        
        Log.i(TAG, "Created default blocklist with ${defaultDomains.size} domains")
    }
    
    /**
     * Получить статистику
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "status" to _status.value,
            "blocked_domains" to (_stats.value["blocked_domains"] ?: 0),
            "total_queries" to (_stats.value["total_queries"] ?: 0),
            "uptime_seconds" to (_stats.value["uptime_seconds"] ?: 0)
        )
    }
    
    /**
     * Проверить домен на фишинг
     */
    fun isPhishing(domain: String): Boolean {
        val blocklistFile = File(context.filesDir, "phishing_domains.txt")
        if (!blocklistFile.exists()) return false
        
        val blocklist = blocklistFile.readLines()
            .map { it.lowercase().trim() }
            .filter { it.isNotBlank() && !it.startsWith("#") }
        
        // Точное совпадение
        if (domain.lowercase() in blocklist) return true
        
        // Проверка паттернов
        val phishingPatterns = listOf(
            "sber", "sberbank", "tinkoff", "tbank", "vtb", "alfa",
            "gosuslugi", "госуслуг"
        )
        
        val suspiciousTlds = listOf(".xyz", ".top", ".tk", ".ml", ".ga", ".cf")
        
        for (pattern in phishingPatterns) {
            if (pattern in domain) {
                for (tld in suspiciousTlds) {
                    if (domain.endsWith(tld)) return true
                }
            }
        }
        
        return false
    }
}
