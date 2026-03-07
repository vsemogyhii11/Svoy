package com.svoy.app.services

import android.content.Context
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.math.abs

/**
 * Voice AI — Анализ звонков в реальном времени
 * 
 * Обнаруживает:
 * - Срочность/давление временем
 * - Ключевые слова мошенников
 * - Синтетический голос (Deepfake)
 * - Эмоциональные манипуляции
 */
class VoiceAIService(private val context: Context) {
    
    companion object {
        private const val TAG = "SVOY_VoiceAI"
        
        // Аудио параметры
        private const val SAMPLE_RATE = 16000
        private const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
        private const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
        
        // Пороги детекции
        private const val URGENCY_THRESHOLD = 0.7
        private const val STRESS_THRESHOLD = 0.6
        private const val DEEPFAKE_THRESHOLD = 0.8
        
        // Ключевые слова мошенников
        val FRAUD_KEYWORDS = listOf(
            // Срочность
            "срочно", "немедленно", "быстро", "сейчас", "5 минут", "10 минут",
            
            // Давление
            "заблокирован", "арест", "полиция", "следователь", "прокурор",
            
            // Деньги
            "перевод", "счёт", "резервный", "безопасный", "код", "смс",
            
            // Угрозы
            "уголовное дело", "ответственность", "суд", "приставы"
        )
    }
    
    // Состояние
    private val _isAnalyzing = MutableStateFlow(false)
    val isAnalyzing = _isAnalyzing.asStateFlow()
    
    private val _riskLevel = MutableStateFlow(0.0)
    val riskLevel = _riskLevel.asStateFlow()
    
    private val _detectedKeywords = MutableStateFlow<List<String>>(emptyList())
    val detectedKeywords = _detectedKeywords.asStateFlow()
    
    // Аудио буфер
    private val audioBuffer = ConcurrentLinkedQueue<Float>()
    
    // Статистика
    private var totalSamples = 0
    private var stressSamples = 0
    
    /**
     * Начать анализ аудио
     */
    fun startAnalysis() {
        if (_isAnalyzing.value) return
        
        _isAnalyzing.value = true
        totalSamples = 0
        stressSamples = 0
        
        Log.i(TAG, "🎤 Voice AI analysis started")
    }
    
    /**
     * Остановить анализ
     */
    fun stopAnalysis() {
        _isAnalyzing.value = false
        audioBuffer.clear()
        
        Log.i(TAG, "Voice AI analysis stopped")
    }
    
    /**
     * Обработать аудио чанк
     */
    fun processAudioChunk(audioData: ShortArray) {
        if (!_isAnalyzing.value) return
        
        for (sample in audioData) {
            val normalized = sample.toFloat() / Short.MAX_VALUE
            audioBuffer.offer(normalized)
            totalSamples++
        }
        
        // Анализ каждые 1000 сэмплов
        if (totalSamples % 1000 == 0) {
            analyzeBuffer()
        }
    }
    
    /**
     * Анализировать аудио буфер
     */
    private fun analyzeBuffer() {
        if (audioBuffer.size < 1000) return
        
        val samples = mutableListOf<Float>()
        while (audioBuffer.isNotEmpty() && samples.size < 1000) {
            samples.add(audioBuffer.poll())
        }
        
        // 1. Детекция стресса (Jitter)
        val jitter = calculateJitter(samples)
        val stressDetected = jitter > STRESS_THRESHOLD
        
        if (stressDetected) {
            stressSamples++
        }
        
        // 2. Детекция срочности (темпы речи)
        val speechRate = calculateSpeechRate(samples)
        val urgencyDetected = speechRate > URGENCY_THRESHOLD
        
        // 3. Обновление риска
        val currentRisk = (
            if (stressDetected) 0.3 else 0.0 +
            if (urgencyDetected) 0.3 else 0.0 +
            if (_detectedKeywords.value.isNotEmpty()) 0.4 else 0.0
        ).coerceIn(0.0, 1.0)
        
        _riskLevel.value = currentRisk
        
        // Предупреждение при высоком риске
        if (currentRisk > 0.7) {
            Log.w(TAG, "⚠️ HIGH RISK DETECTED: $currentRisk")
        }
    }
    
    /**
     * Расчитать Jitter (показатель стресса)
     */
    private fun calculateJitter(samples: List<Float>): Float {
        if (samples.size < 2) return 0f
        
        var sumDiff = 0f
        for (i in 1 until samples.size) {
            sumDiff += abs(abs(samples[i]) - abs(samples[i - 1]))
        }
        
        return sumDiff / samples.size
    }
    
    /**
     * Расчитать темп речи
     */
    private fun calculateSpeechRate(samples: List<Float>): Float {
        // Подсчёт zero crossings (приближение к темпу)
        var zeroCrossings = 0
        for (i in 1 until samples.size) {
            if ((samples[i] >= 0) != (samples[i - 1] >= 0)) {
                zeroCrossings++
            }
        }
        
        // Нормализация
        return (zeroCrossings.toFloat() / samples.size).coerceIn(0f, 1f)
    }
    
    /**
     * Обработать текст из речи (после STT)
     */
    fun processTranscribedText(text: String) {
        val lowerText = text.lowercase()
        val foundKeywords = mutableListOf<String>()
        
        for (keyword in FRAUD_KEYWORDS) {
            if (keyword in lowerText) {
                foundKeywords.add(keyword)
            }
        }
        
        if (foundKeywords.isNotEmpty()) {
            _detectedKeywords.value = foundKeywords
            
            // Увеличить риск
            val keywordRisk = (foundKeywords.size * 0.1).coerceIn(0.0, 0.4)
            _riskLevel.value = (_riskLevel.value + keywordRisk).coerceIn(0.0, 1.0)
            
            Log.w(TAG, "🔑 Keywords detected: $foundKeywords")
        }
    }
    
    /**
     * Детектировать Deepfake (упрощённо)
     */
    fun detectDeepfake(audioFeatures: Map<String, Float>): Boolean {
        // Признаки deepfake:
        // - Неестественные паузы
        // - Артефакты сжатия
        // - Несоответствие питча
        
        val unnaturalPauses = audioFeatures["unnatural_pauses"] ?: 0f
        val compressionArtifacts = audioFeatures["compression_artifacts"] ?: 0f
        val pitchMismatch = audioFeatures["pitch_mismatch"] ?: 0f
        
        val deepfakeScore = (
            unnaturalPauses * 0.3 +
            compressionArtifacts * 0.4 +
            pitchMismatch * 0.3
        )
        
        return deepfakeScore > DEEPFAKE_THRESHOLD
    }
    
    /**
     * Получить статистику
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "is_analyzing" to _isAnalyzing.value,
            "current_risk" to _riskLevel.value,
            "keywords_detected" to _detectedKeywords.value.size,
            "stress_ratio" to (if (totalSamples > 0) stressSamples.toFloat() / totalSamples else 0f)
        )
    }
}
