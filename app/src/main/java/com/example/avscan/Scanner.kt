package com.example.avscan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest

data class Finding(val name: String, val pkg: String, val score: Int, val verdict: String, val reasons: List<String>) {
    val level get() = when { score >= 60 -> "ALTO"; score >= 30 -> "MÉDIO"; else -> "BAIXO" }
}

object Scanner {
    private const val P = "android.permission."
    private val perms = mapOf(
        P + "READ_SMS" to 15, P + "RECEIVE_SMS" to 10, P + "SEND_SMS" to 15,
        P + "READ_CALL_LOG" to 10, P + "READ_CONTACTS" to 5, P + "RECORD_AUDIO" to 5,
        P + "SYSTEM_ALERT_WINDOW" to 15, P + "REQUEST_INSTALL_PACKAGES" to 15,
        P + "RECEIVE_BOOT_COMPLETED" to 3
    )
    private val servicePerms = mapOf(
        P + "BIND_ACCESSIBILITY_SERVICE" to ("Serviço de acessibilidade (usado por trojans bancários)" to 25),
        P + "BIND_DEVICE_ADMIN" to ("Administrador do dispositivo (dificulta remoção)" to 25),
        P + "BIND_NOTIFICATION_LISTENER_SERVICE" to ("Lê todas as notificações (rouba códigos 2FA)" to 15)
    )
    // Apps conhecidos: só são ignorados se vierem de loja confiável (um falso instalado por APK não passa)
    private val knownGood = setOf(
        "com.whatsapp", "com.whatsapp.w4b", "com.avast.android.mobilesecurity", "com.discord",
        "com.ubercab", "com.instagram.android", "com.facebook.katana", "org.telegram.messenger",
        "com.google.android.apps.messaging", "com.nu.production", "br.com.intermedium",
        "com.mercadopago.wallet", "com.spotify.music", "com.netflix.mediaclient", "com.google.android.youtube"
    )
    private val trustedStores = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia", "com.epicgames.portal")

    fun scan(ctx: Context, badHashes: Set<String>): List<Finding> {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
        val list: List<PackageInfo> = if (Build.VERSION.SDK_INT >= 33)
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
        return list.filter { it.packageName != ctx.packageName }
            .mapNotNull { analyze(pm, it, badHashes) }
            .sortedByDescending { it.score }
    }

    private fun analyze(pm: PackageManager, pi: PackageInfo, bad: Set<String>): Finding? {
        val ai = pi.applicationInfo ?: return null
        val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
        if (isSystem) return null
        var score = 0
        val why = mutableListOf<String>()

        val hash = sha256(ai.sourceDir)
        if (hash != null && hash in bad) { score += 100; why += "Hash idêntico a malware conhecido" }

        val requested = pi.requestedPermissions?.toSet() ?: emptySet()
        for ((p, pts) in perms) if (p in requested) { score += pts; why += "Permissão ${p.removePrefix(P)}" }
        if (P + "READ_SMS" in requested && P + "INTERNET" in requested) { score += 10; why += "Lê SMS e acessa a internet" }

        var stealth = false
        pi.services?.forEach { s ->
            servicePerms[s.permission]?.let { (txt, pts) -> score += pts; why += txt; stealth = true }
        }

        val installer = if (Build.VERSION.SDK_INT >= 30)
            runCatching { pm.getInstallSourceInfo(pi.packageName).installingPackageName }.getOrNull()
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(pi.packageName)
        val sideload = installer !in trustedStores
        if (!sideload && pi.packageName in knownGood) return null
        if (sideload) { score += 15; why += "Instalado fora de loja confiável (${installer ?: "APK manual"})" }

        if (pm.getLaunchIntentForPackage(pi.packageName) == null) { score += 10; why += "Sem ícone no menu (app oculto)" }

        if (score == 0) return null
        val sms = P + "READ_SMS" in requested
        val overlay = P + "SYSTEM_ALERT_WINDOW" in requested
        val net = P + "INTERNET" in requested
        val hashHit = hash != null && hash in bad
        val verdict = when {
            hashHit -> "MALWARE CONHECIDO"
            sideload && stealth && (sms || overlay) -> "Possível trojan bancário"
            sideload && sms && net -> "Possível spyware de SMS"
            stealth && !sideload -> "Usa recursos avançados, mas veio de loja confiável: normalmente ok"
            stealth -> "Recursos de espionagem: confirme que você reconhece o app"
            score >= 60 -> "Muitas permissões sensíveis"
            sideload -> "Provavelmente legítimo, mas instalado fora da loja"
            else -> "Permissões comuns"
        }
        if (verdict == "Permissões comuns") return null
        return Finding(pm.getApplicationLabel(ai).toString(), pi.packageName, score.coerceAtMost(100), verdict, why)
    }

    private fun sha256(path: String): String? = runCatching {
        val md = MessageDigest.getInstance("SHA-256")
        File(path).inputStream().use { s -> val b = ByteArray(8192); while (true) { val n = s.read(b); if (n < 0) break; md.update(b, 0, n) } }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()
}
