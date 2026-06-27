package com.green.agent

import android.content.Context
import android.provider.Settings

data class PrivateDnsState(
    val mode: String,
    val specifier: String
) {
    val isStrict: Boolean
        get() = mode == "hostname"

    val displayText: String
        get() = when (mode) {
            "off" -> "Private DNS: Off"
            "opportunistic" -> "Private DNS: Automatic"
            "hostname" -> "Private DNS: Enabled (${specifier.ifBlank { "provider" }})"
            else -> "Private DNS: Unknown"
        }
}

fun readPrivateDnsState(context: Context): PrivateDnsState {
    val mode = Settings.Global.getString(context.contentResolver, "private_dns_mode")
        ?: Settings.Global.getString(context.contentResolver, "private_dns_default_mode")
        ?.trim()
        ?.lowercase()
        ?: "unknown"
    val specifier = Settings.Global.getString(context.contentResolver, "private_dns_specifier")
        ?.trim()
        ?: ""
    return PrivateDnsState(mode, specifier)
}
