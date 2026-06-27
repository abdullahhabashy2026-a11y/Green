package com.green.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

class GreenVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private val classifier = DomainClassifier()
    private val lastLogged = ConcurrentHashMap<String, Long>()
    private val domainCheckCache = ConcurrentHashMap<String, CachedDecision>()
    private var vpnInterface: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            else -> startVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn() {
        if (running.get()) return
        val config = ConfigStore(this).load()
        if (!config.isActivated) {
            stopSelf()
            return
        }
        startForeground(NOTIFICATION_ID, notification("Blocking is active"))
        vpnInterface = Builder()
            .setSession("Green DNS Filter")
            .addAddress("10.111.0.2", 32)
            .addDnsServer("10.111.0.1")
            .addRoute("10.111.0.1", 32)
            .setBlocking(true)
            .establish()
        running.set(true)
        Thread { blocklistLoop(config) }.apply {
            name = "GreenVpnBlocklistLoop"
            start()
        }
        worker = Thread { runLoop(config) }.apply {
            name = "GreenVpnDnsLoop"
            start()
        }
        Thread { heartbeatLoop(config) }.apply {
            name = "GreenVpnHeartbeatLoop"
            start()
        }
    }

    private fun stopVpn() {
        if (!running.getAndSet(false)) {
            stopSelf()
            return
        }
        try {
            ConfigStore(this).load().takeIf { it.isActivated }?.let {
                ApiClient(it.serverUrl).heartbeat(
                    config = it,
                    status = "running",
                    privateDnsState = readPrivateDnsState(this),
                    vpnActive = false,
                    batteryOptimizationIgnored = isBatteryOptimizationIgnored(this)
                )
            }
        } catch (_: Exception) {
        }
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun runLoop(config: AppConfig) {
        val descriptor = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(descriptor)
        val output = FileOutputStream(descriptor)
        val api = ApiClient(config.serverUrl)
        while (running.get()) {
            try {
                val buffer = ByteArray(32767)
                val length = input.read(buffer)
                if (length <= 0) continue
                val packet = IpPacket.parseUdpDnsPacket(buffer, length) ?: continue
                val query = DnsMessage.parseQuery(packet.dnsPayload) ?: continue
                val decision = classifyWithServerFallback(config, api, query.domain)
                val dnsResponse = if (decision.decision == "blocked") {
                    logBlocked(config, api, decision)
                    DnsMessage.blockedResponse(packet.dnsPayload, query)
                } else {
                    forwardDns(packet.dnsPayload)
                }
                val responsePacket = IpPacket.buildUdpResponse(packet, dnsResponse)
                output.write(responsePacket)
            } catch (_: Exception) {
                Thread.sleep(50)
            }
        }
    }

    private fun classifyWithServerFallback(config: AppConfig, api: ApiClient, domain: String): DomainDecision {
        val localDecision = classifier.classify(domain)
        if (localDecision.decision == "blocked" || localDecision.category == "allowed") {
            return localDecision
        }

        val normalized = normalizeDomain(domain)
        val now = System.currentTimeMillis()
        domainCheckCache[normalized]?.let {
            if (now < it.expiresAtMs) {
                return it.decision
            }
        }

        val serverDecision = runCatching { api.checkDomain(config, normalized) }
            .getOrElse { localDecision }
        domainCheckCache[normalized] = CachedDecision(serverDecision, now + DOMAIN_CHECK_CACHE_MS)
        return serverDecision
    }

    private fun heartbeatLoop(config: AppConfig) {
        val api = ApiClient(config.serverUrl)
        while (running.get()) {
            runCatching {
                api.heartbeat(
                    config = config,
                    status = "blocking",
                    privateDnsState = readPrivateDnsState(this),
                    vpnActive = true,
                    batteryOptimizationIgnored = isBatteryOptimizationIgnored(this)
                )
            }
            sleepInterruptibly(HEARTBEAT_MS)
        }
    }

    private fun blocklistLoop(config: AppConfig) {
        val api = ApiClient(config.serverUrl)
        while (running.get()) {
            val blocklist = runCatching { api.fetchBlocklist(config) }
                .getOrElse { LocalBlocklist.load(this) }
            classifier.updateDynamicDomains(blocklist.domains)
            classifier.updateBlockedKeywords(blocklist.keywords)
            sleepInterruptibly(BLOCKLIST_REFRESH_MS)
        }
    }

    private fun sleepInterruptibly(durationMs: Long) {
        var remaining = durationMs
        while (running.get() && remaining > 0) {
            val step = minOf(1000L, remaining)
            Thread.sleep(step)
            remaining -= step
        }
    }

    private fun forwardDns(payload: ByteArray): ByteArray {
        val socket = DatagramSocket()
        protect(socket)
        socket.soTimeout = 4000
        socket.use {
            val upstream = InetAddress.getByName("8.8.8.8")
            it.send(DatagramPacket(payload, payload.size, upstream, 53))
            val response = ByteArray(4096)
            val packet = DatagramPacket(response, response.size)
            it.receive(packet)
            return response.copyOf(packet.length)
        }
    }

    private fun logBlocked(config: AppConfig, api: ApiClient, decision: DomainDecision) {
        val now = System.currentTimeMillis()
        val key = "${decision.domain}:${decision.decision}"
        val previous = lastLogged[key] ?: 0L
        if (now - previous < LOG_THROTTLE_MS) return
        lastLogged[key] = now
        Thread {
            runCatching { api.domainEvent(config, decision) }
        }.start()
    }

    private fun notification(text: String): Notification {
        val channelId = "green_vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(channelId, "Green protection", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val intent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, channelId)
            .setContentTitle("Green")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(intent)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_STOP = "com.green.agent.STOP_VPN"
        private const val NOTIFICATION_ID = 2001
        private const val HEARTBEAT_MS = 60_000L
        private const val BLOCKLIST_REFRESH_MS = 300_000L
        private const val LOG_THROTTLE_MS = 30_000L
        private const val DOMAIN_CHECK_CACHE_MS = 300_000L
    }
}

private data class CachedDecision(
    val decision: DomainDecision,
    val expiresAtMs: Long
)
