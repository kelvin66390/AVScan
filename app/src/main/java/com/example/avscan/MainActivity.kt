package com.example.avscan

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.*

class MainActivity : Activity() {
    private var results = listOf<Finding>()

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val status = TextView(this).apply { text = "Toque em Verificar para analisar seus apps."; textSize = 16f; setPadding(32, 32, 32, 16) }
        val btn = Button(this).apply { text = "Verificar agora" }
        val list = ListView(this)
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.TOP
            addView(status); addView(btn); addView(list)
        })

        btn.setOnClickListener {
            btn.isEnabled = false; status.text = "Analisando…"
            Thread {
                val hashes = assets.open("signatures.txt").bufferedReader().readLines()
                    .map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
                val r = Scanner.scan(this, hashes)
                runOnUiThread {
                    results = r; btn.isEnabled = true
                    status.text = if (r.isEmpty()) "Nenhuma ameaça encontrada." else "${r.size} app(s) suspeito(s):"
                    list.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, android.R.id.text1,
                        r.map { "[${it.level}] ${it.name}\n${it.verdict}" })
                }
            }.start()
        }

        list.setOnItemClickListener { _, _, i, _ ->
            val f = results[i]
            AlertDialog.Builder(this).setTitle("${f.name} — risco ${f.level} (${f.score})")
                .setMessage(f.verdict + "\n\n" + f.reasons.joinToString("\n• ", prefix = "• "))
                .setPositiveButton("Desinstalar") { _, _ ->
                    startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:${f.pkg}")))
                }
                .setNegativeButton("Fechar", null).show()
        }
    }
}
