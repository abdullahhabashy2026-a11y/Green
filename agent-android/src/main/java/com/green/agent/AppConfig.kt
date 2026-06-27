package com.green.agent

data class AppConfig(
    val serverUrl: String,
    val deviceId: String,
    val token: String,
    val recoveryName: String
) {
    val isActivated: Boolean
        get() = deviceId.isNotBlank() && token.isNotBlank()
}
