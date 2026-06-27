package com.green.agent

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {
    private lateinit var store: ConfigStore
    private lateinit var serverInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var statusText: TextView
    private lateinit var privateDnsText: TextView
    private lateinit var activateButton: Button
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private val handler = Handler(Looper.getMainLooper())
    private var heartbeatRunning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ConfigStore(this)
        buildUi()
        loadConfig()
        requestNotificationPermission()
        startHeartbeatLoop()
    }

    override fun onDestroy() {
        heartbeatRunning = false
        super.onDestroy()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService()
        }
    }

    private fun buildUi() {
        val padding = dp(18)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, padding)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }
        layout.addView(title("Green Android Agent"))
        layout.addView(label("Server URL"))
        serverInput = editText("http://10.0.2.2:8000")
        layout.addView(serverInput)
        layout.addView(label("Activation Token"))
        tokenInput = editText("")
        layout.addView(tokenInput)
        activateButton = button("Activate") { activate() }
        layout.addView(activateButton)
        statusText = label("Not activated")
        layout.addView(statusText)
        privateDnsText = label(readPrivateDnsState(this).displayText)
        layout.addView(privateDnsText)
        layout.addView(button("Open Private DNS Settings") { openPrivateDnsSettings() })
        startButton = button("Start Blocking") { prepareVpn() }
        layout.addView(startButton)
        stopButton = button("Stop Blocking") { stopVpnService() }
        layout.addView(stopButton)
        setContentView(layout)
    }

    private fun loadConfig() {
        val config = store.load()
        serverInput.setText(config.serverUrl)
        if (config.isActivated) {
            statusText.text = "Activated: ${config.recoveryName.ifBlank { config.deviceId }}"
            activateButton.isEnabled = false
        }
    }

    private fun activate() {
        val serverUrl = serverInput.text.toString().trim().trimEnd('/')
        val token = tokenInput.text.toString().trim()
        if (serverUrl.isBlank() || token.isBlank()) {
            toast("Server URL and token are required")
            return
        }
        activateButton.isEnabled = false
        statusText.text = "Activating..."
        Thread {
            try {
                val config = ApiClient(serverUrl).activate(token)
                store.save(config)
                runOnUiThread {
                    statusText.text = "Activated: ${config.recoveryName.ifBlank { config.deviceId }}"
                    tokenInput.setText("")
                    toast("Activated")
                }
            } catch (error: Exception) {
                runOnUiThread {
                    statusText.text = "Activation failed"
                    activateButton.isEnabled = true
                    toast(error.message ?: "Activation failed")
                }
            }
        }.start()
    }

    private fun prepareVpn() {
        val config = store.load()
        if (!config.isActivated) {
            toast("Activate first")
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, VPN_REQUEST_CODE)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val config = store.load()
        val intent = Intent(this, GreenVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        statusText.text = "Blocking active"
        if (config.isActivated) {
            val privateDnsState = readPrivateDnsState(this)
            Thread {
                runCatching {
                    ApiClient(config.serverUrl).heartbeat(
                        config = config,
                        status = "blocking",
                        privateDnsState = privateDnsState,
                        vpnActive = true,
                        batteryOptimizationIgnored = isBatteryOptimizationIgnored(this)
                    )
                }
            }.start()
        }
    }

    private fun stopVpnService() {
        val config = store.load()
        val intent = Intent(this, GreenVpnService::class.java).setAction(GreenVpnService.ACTION_STOP)
        startService(intent)
        statusText.text = "Blocking stopped"
        if (config.isActivated) {
            val privateDnsState = readPrivateDnsState(this)
            Thread {
                runCatching {
                    ApiClient(config.serverUrl).heartbeat(
                        config = config,
                        status = "running",
                        privateDnsState = privateDnsState,
                        vpnActive = false,
                        batteryOptimizationIgnored = isBatteryOptimizationIgnored(this)
                    )
                }
            }.start()
        }
    }

    private fun startHeartbeatLoop() {
        heartbeatRunning = true
        handler.post(object : Runnable {
            override fun run() {
                val config = store.load()
                val privateDnsState = readPrivateDnsState(this@MainActivity)
                privateDnsText.text = privateDnsState.displayText
                if (config.isActivated) {
                    Thread {
                        runCatching {
                            ApiClient(config.serverUrl).heartbeat(
                                config = config,
                                status = "running",
                                privateDnsState = privateDnsState,
                                batteryOptimizationIgnored = isBatteryOptimizationIgnored(this@MainActivity)
                            )
                            runOnUiThread { statusText.text = "Active: heartbeat sent" }
                        }
                    }.start()
                }
                if (heartbeatRunning) {
                    handler.postDelayed(this, 60_000L)
                }
            }
        })
    }

    private fun openPrivateDnsSettings() {
        try {
            startActivity(Intent("android.settings.PRIVATE_DNS_SETTINGS"))
        } catch (_: Exception) {
            startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS))
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 3001)
        }
    }

    private fun title(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 24f
        setPadding(0, 0, 0, dp(18))
    }

    private fun label(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 16f
        setPadding(0, dp(10), 0, dp(6))
    }

    private fun editText(hintText: String): EditText = EditText(this).apply {
        hint = hintText
        setSingleLine(true)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        )
    }

    private fun button(text: String, click: () -> Unit): Button = Button(this).apply {
        this.text = text
        setOnClickListener { click() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = dp(12)
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        private const val VPN_REQUEST_CODE = 1001
    }
}
