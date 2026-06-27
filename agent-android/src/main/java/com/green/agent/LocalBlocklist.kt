package com.green.agent

import android.content.Context

object LocalBlocklist {
    private val categories = listOf("adult", "social", "custom")

    @Volatile
    private var cached: BlocklistPayload? = null

    fun load(context: Context): BlocklistPayload {
        cached?.let { return it }

        val domains = LinkedHashMap<String, String>()
        for (category in categories) {
            val assetName = "$category.txt"
            runCatching {
                context.assets.open(assetName).bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach { line ->
                        val domain = parseBlocklistLine(line)
                        if (isValidDomain(domain)) {
                            domains[domain] = category
                        }
                    }
                }
            }
        }

        return BlocklistPayload(domains, emptyList()).also {
            cached = it
        }
    }

    private fun parseBlocklistLine(line: String): String {
        var value = line.trim()
        if (value.isBlank() || value.startsWith("#") || value.startsWith("!") ||
            value.startsWith("[") || value.startsWith("@@")
        ) {
            return ""
        }

        value = when {
            value.startsWith("||") -> value.removePrefix("||").substringBefore("^").substringBefore("$")
            value.startsWith("|") -> value.trimStart('|').substringBefore("^").substringBefore("$")
            else -> {
                val parts = value.replace("\t", " ").split(" ").filter { it.isNotBlank() }
                if (parts.size >= 2 && parts[0] in setOf("0.0.0.0", "127.0.0.1", "::", "::1")) {
                    parts[1]
                } else {
                    parts.firstOrNull().orEmpty()
                }
            }
        }

        if (value.startsWith("*.")) {
            value = value.removePrefix("*.")
        }
        return normalizeLocalDomain(value.trim().trim('|').trim('^'))
    }

    private fun normalizeLocalDomain(domain: String): String {
        var value = domain.trim().lowercase().trimEnd('.')
        if ("://" in value) {
            value = value.substringAfter("://")
        }
        value = value.substringBefore("/").substringBefore("?").substringBefore("#")
        if (value.startsWith("www.")) {
            value = value.removePrefix("www.")
        }
        return value
    }

    private fun isValidDomain(value: String): Boolean {
        if (value.isBlank() || value.length > 255 || "." !in value) {
            return false
        }
        return value.split(".").all { label ->
            label.isNotBlank() && label.all { it.isLetterOrDigit() || it == '-' }
        }
    }
}
