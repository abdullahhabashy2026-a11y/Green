package com.green.agent

import android.content.Context

class ConfigStore(context: Context) {
    private val prefs = context.getSharedPreferences("green_agent", Context.MODE_PRIVATE)

    fun load(): AppConfig = AppConfig(
        serverUrl = prefs.getString("server_url", DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL,
        deviceId = prefs.getString("device_id", "") ?: "",
        token = prefs.getString("token", "") ?: "",
        recoveryName = prefs.getString("recovery_name", "") ?: ""
    )

    fun save(config: AppConfig) {
        prefs.edit()
            .putString("server_url", config.serverUrl.trim().trimEnd('/'))
            .putString("device_id", config.deviceId)
            .putString("token", config.token)
            .putString("recovery_name", config.recoveryName)
            .apply()
    }

    companion object {
        const val DEFAULT_SERVER_URL = "http://10.0.2.2:8000"
        const val APP_VERSION = "0.1.0-android"
    }
}
