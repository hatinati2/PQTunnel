package org.pqtunnel.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import org.pqtunnel.mobile.ClientHandle
import org.pqtunnel.mobile.Mobile
import org.pqtunnel.mobile.SocketProtector
import java.io.File

class PQTunnelVpnService : VpnService() {
    @Volatile private var tunnel: ParcelFileDescriptor? = null
    @Volatile private var client: ClientHandle? = null
    @Volatile private var stopped = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1001, notification())
        Thread({ startTunnel() }, "pqtunnel-start").start()
        return START_NOT_STICKY
    }

    private fun startTunnel() {
        try {
            val pki = File(filesDir, "pki")
            val ca = File(pki, "ca.crt").readBytes()
            val cert = File(pki, "client.crt").readBytes()
            val key = File(pki, "client.key").readBytes()
            if (stopped) return
            val builder = Builder()
                .setSession("PQTunnel")
                .setMtu(1280)
                .addAddress(getString(R.string.client_ip), 32)
                .addAddress("fd66:66::2", 128)
                .addRoute("0.0.0.0", 0)
                // IPv6 is routed into the VPN but intentionally dropped by the v1 core.
                // This prevents a direct IPv6 path at the cost of IPv6 connectivity.
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
            val established = builder.establish() ?: throw IllegalStateException("VpnService.establish failed")
            tunnel = established
            val ownedFd = ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
            val protector = object : SocketProtector {
                override fun protect(fd: Int): Boolean = this@PQTunnelVpnService.protect(fd)
            }
            val handle = Mobile.startClientFD(
                ownedFd,
                getString(R.string.server_address),
                getString(R.string.server_name),
                ca, cert, key, getString(R.string.client_ip), protector
            )
            client = handle
            if (stopped) handle.stop()
        } catch (t: Throwable) {
            stopSelf()
        }
    }

    private fun notification(): Notification {
        val channelId = "pqtunnel-vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(channelId, "PQTunnel VPN", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, channelId) else Notification.Builder(this)
        return builder.setContentTitle("PQTunnel").setContentText("Encrypted tunnel service running")
            .setSmallIcon(android.R.drawable.stat_sys_warning).setContentIntent(open).setOngoing(true).build()
    }

    override fun onDestroy() {
        stopped = true
        try { client?.stop() } catch (_: Throwable) {}
        try { tunnel?.close() } catch (_: Throwable) {}
        client = null; tunnel = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
