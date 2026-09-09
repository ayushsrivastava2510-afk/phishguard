package com.binarybattalion.phishguard.core

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.media.ToneGenerator
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import com.binarybattalion.phishguard.R

/**
 * Singleton controller that manages high-priority audio & haptic alerts
 * for incoming SMS messages evaluated with a critical threat score exceeding 90/100.
 * Automatically enforces a strict 3.0-second playback duration.
 */
object ThreatSirenPlayer {

    private const val TAG = "ThreatSirenPlayer"
    const val SIREN_DURATION_MS = 3000L

    private var mediaPlayer: MediaPlayer? = null
    private var isPlaying = false
    private val mainHandler = Handler(Looper.getMainLooper())
    private var stopRunnable: Runnable? = null

    /**
     * Plays the emergency siren audio and fires a synchronized haptic pulse pattern.
     * Guaranteed to stop automatically after [durationMs] (default: 3000 ms).
     */
    @Synchronized
    fun playSiren(context: Context, durationMs: Long = SIREN_DURATION_MS) {
        if (isPlaying) {
            Log.d(TAG, "Siren is already playing; ignoring duplicate trigger")
            return
        }

        try {
            stop() // Clean up any lingering instance

            isPlaying = true
            val appContext = context.applicationContext

            // 1. Trigger synchronized emergency vibration pattern
            triggerVibration(appContext)

            // 2. Initialize and start MediaPlayer
            val player = MediaPlayer.create(appContext, R.raw.threat_siren_3s)

            if (player != null) {
                mediaPlayer = player
                player.setAudioAttributes(
                    AudioAttributes.Builder()
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .setUsage(AudioAttributes.USAGE_ALARM)
                        .build()
                )
                player.isLooping = false
                player.setVolume(1.0f, 1.0f)
                player.setOnCompletionListener {
                    stop()
                }
                player.setOnErrorListener { _, what, extra ->
                    Log.e(TAG, "MediaPlayer error ($what, $extra), switching to fallback tone")
                    fallbackTone(durationMs)
                    true
                }
                player.start()
                Log.i(TAG, "🚨 3-second threat siren started")
            } else {
                Log.w(TAG, "MediaPlayer.create returned null for R.raw.threat_siren_3s, using tone fallback")
                fallbackTone(durationMs)
            }

            // 3. Enforce strict 3.0-second auto-stop
            val runnable = Runnable {
                Log.i(TAG, "Siren 3-second timer expired; stopping playback")
                stop()
            }
            stopRunnable = runnable
            mainHandler.postDelayed(runnable, durationMs)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start siren alert", e)
            fallbackTone(durationMs)
        }
    }

    private fun fallbackTone(durationMs: Long) {
        try {
            val toneGen = ToneGenerator(AudioManager.STREAM_ALARM, 100)
            toneGen.startTone(ToneGenerator.TONE_CDMA_EMERGENCY_RINGBACK, durationMs.toInt())
            mainHandler.postDelayed({
                try {
                    toneGen.release()
                } catch (_: Exception) {}
                isPlaying = false
            }, durationMs)
        } catch (e: Exception) {
            Log.e(TAG, "Fallback tone generation failed", e)
            isPlaying = false
        }
    }

    private fun triggerVibration(context: Context) {
        try {
            // Rapid multi-pulse emergency warning pattern over 3 seconds
            val pattern = longArrayOf(0, 350, 150, 350, 150, 350, 150, 350, 150, 350)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val manager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                manager?.defaultVibrator?.vibrate(VibrationEffect.createWaveform(pattern, -1))
            } else {
                @Suppress("DEPRECATION")
                val vibrator = context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator?.vibrate(VibrationEffect.createWaveform(pattern, -1))
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(pattern, -1)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Vibration execution failed", e)
        }
    }

    /**
     * Instantly terminates siren playback and releases hardware resources.
     */
    @Synchronized
    fun stop() {
        stopRunnable?.let { mainHandler.removeCallbacks(it) }
        stopRunnable = null

        try {
            mediaPlayer?.let {
                if (it.isPlaying) {
                    it.stop()
                }
                it.release()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping MediaPlayer", e)
        } finally {
            mediaPlayer = null
            isPlaying = false
        }
    }

    fun isSirenPlaying(): Boolean = isPlaying
}
