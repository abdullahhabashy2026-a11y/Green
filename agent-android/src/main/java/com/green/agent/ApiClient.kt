package com.green.agent

import android.os.Build
import org.json.JSONObject
import java.io.BufferedReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class BlocklistPayload(
    val domains: Map<String, String>,
    val keywords: List<String>
)

class ApiClient(private val serverUrl: String) {
    fun activate(enrollmentToken: String): AppConfig {
        val response = postJson(
            "/api/activate",
            JSONObject()
                .put("enrollment_token", enrollmentToken.trim())
                .put("device_name", deviceName())
                .put("windows_user", "android")
                .put("platform", "android")
                .put("agent_version", ConfigStore.APP_VERSION)
        )
        return AppConfig(
            serverUrl = serverUrl.trim().trimEnd('/'),
            deviceId = response.getString("device_id"),
            token = response.getString("token"),
            recoveryName = response.optString("recovery_name", "")
        )
    }

    fun heartbeat(
        config: AppConfig,
        status: String,
        privateDnsState: PrivateDnsState? = null,
        vpnActive: Boolean? = null,
        batteryOptimizationIgnored: Boolean? = null
    ) {
        val body = JSONObject()
            .put("device_id", config.deviceId)
            .put("token", config.token)
            .put("device_name", deviceName())
            .put("windows_user", "android")
            .put("platform", "android")
            .put("agent_version", ConfigStore.APP_VERSION)
            .put("status", status)
        if (privateDnsState != null) {
            body.put("private_dns_mode", privateDnsState.mode)
            body.put("private_dns_specifier", privateDnsState.specifier)
        }
        if (vpnActive != null) {
            body.put("vpn_active", vpnActive)
        }
        if (batteryOptimizationIgnored != null) {
            body.put("battery_optimization_ignored", batteryOptimizationIgnored)
        }
        postJson("/api/heartbeat", body)
    }

    fun fetchBlocklist(config: AppConfig): BlocklistPayload {
        val url = URL(
            "${config.serverUrl.trimEnd('/')}/api/blocklist" +
                "?device_id=${encode(config.deviceId)}&token=${encode(config.token)}"
        )
        val payload = request("GET", url, null)
        val domainArray = payload.optJSONArray("blocked_domains")
        val domains = LinkedHashMap<String, String>()
        if (domainArray != null) {
            for (index in 0 until domainArray.length()) {
                val item = domainArray.optJSONObject(index) ?: continue
                val domain = normalizeDomain(item.optString("domain", ""))
                val category = item.optString("category", "").trim().lowercase()
                if (domain.isNotBlank() && category.isNotBlank()) {
                    domains[domain] = category
                }
            }
        }
        val keywordArray = payload.optJSONArray("blocked_keywords")
        val keywords = mutableListOf<String>()
        if (keywordArray != null) {
            for (index in 0 until keywordArray.length()) {
                val item = keywordArray.optJSONObject(index) ?: continue
                val keyword = item.optString("keyword", "").trim().lowercase()
                if (keyword.isNotBlank()) {
                    keywords += keyword
                }
            }
        }
        return BlocklistPayload(domains, keywords)
    }

    fun domainEvent(config: AppConfig, decision: DomainDecision) {
        postJson(
            "/api/domain-event",
            JSONObject()
                .put("device_id", config.deviceId)
                .put("token", config.token)
                .put("domain", decision.domain)
                .put("category", decision.category)
                .put("decision", decision.decision)
                .put("reason", decision.reason)
        )
    }

    fun checkDomain(config: AppConfig, domain: String): DomainDecision {
        val response = postJson(
            "/api/domain-check",
            JSONObject()
                .put("device_id", config.deviceId)
                .put("token", config.token)
                .put("domain", domain)
        )
        return DomainDecision(
            domain = response.optString("domain", normalizeDomain(domain)),
            category = response.optString("category", "unknown"),
            decision = response.optString("decision", "allowed"),
            reason = response.optString("reason", "No server response reason")
        )
    }

    private fun postJson(path: String, body: JSONObject): JSONObject {
        val url = URL("${serverUrl.trimEnd('/')}$path")
        return request("POST", url, body)
    }

    private fun request(method: String, url: URL, body: JSONObject?): JSONObject {
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15000
            readTimeout = 15000
            setRequestProperty("Accept", "application/json")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        if (body != null) {
            OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(body.toString()) }
        }
        val stream = if (connection.responseCode in 200..299) {
            connection.inputStream
        } else {
            connection.errorStream ?: connection.inputStream
        }
        val text = BufferedReader(stream.reader(Charsets.UTF_8)).use { it.readText() }
        if (connection.responseCode !in 200..299) {
            throw IllegalStateException("HTTP ${connection.responseCode}: $text")
        }
        return JSONObject(text)
    }

    private fun deviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    private fun encode(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")
}
