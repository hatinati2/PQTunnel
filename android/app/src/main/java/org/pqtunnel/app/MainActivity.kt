package org.pqtunnel.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private val requestVpnCode = 4102
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        status = TextView(this).apply { text = "PQTunnel prototype\nHybrid PQ key exchange is required." }
        val start = Button(this).apply {
            text = "Connect"
            setOnClickListener {
                val intent = VpnService.prepare(this@MainActivity)
                if (intent != null) startActivityForResult(intent, requestVpnCode) else connect()
            }
        }
        val stop = Button(this).apply { text = "Disconnect"; setOnClickListener { stopService(Intent(this@MainActivity, PQTunnelVpnService::class.java)); status.text = "Disconnected" } }
        layout.addView(status); layout.addView(start); layout.addView(stop); setContentView(layout)
    }

    @Deprecated("legacy callback kept to avoid an extra AndroidX dependency in the scaffold")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == requestVpnCode && resultCode == RESULT_OK) connect()
        else status.text = "VPN permission was not granted"
    }

    private fun connect() {
        startForegroundService(Intent(this, PQTunnelVpnService::class.java))
        status.text = "Connecting. Certificates must be present in the app's private files/pki directory."
    }
}
