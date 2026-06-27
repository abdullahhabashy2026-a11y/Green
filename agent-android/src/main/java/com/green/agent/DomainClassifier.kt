package com.green.agent

data class DomainDecision(
    val domain: String,
    val category: String,
    val decision: String,
    val reason: String
)

fun normalizeDomain(domain: String): String = domain.trim().lowercase().trimEnd('.')

fun domainSuffixes(domain: String): List<String> {
    val labels = normalizeDomain(domain).split('.').filter { it.isNotBlank() }
    return labels.indices.map { labels.drop(it).joinToString(".") }
}

fun matchesSuffix(domain: String, suffix: String): Boolean {
    return domain == suffix || domain.endsWith(".$suffix")
}

class DomainClassifier {
    @Volatile
    private var dynamicDomains: Map<String, String> = emptyMap()

    @Volatile
    private var blockedKeywords: Set<String> = emptySet()

    fun updateDynamicDomains(domains: Map<String, String>) {
        dynamicDomains = domains
            .mapKeys { normalizeDomain(it.key) }
            .filterKeys { domain -> domain.isNotBlank() && ALLOW_SUFFIXES.none { matchesSuffix(domain, it) } }
    }

    fun updateBlockedKeywords(keywords: List<String>) {
        blockedKeywords = keywords.map { it.trim().lowercase() }.filter { it.isNotBlank() }.toSet()
    }

    fun classify(domain: String): DomainDecision {
        val normalized = normalizeDomain(domain)
        ALLOW_SUFFIXES.firstOrNull { matchesSuffix(normalized, it) }?.let {
            return DomainDecision(normalized, "allowed", "allowed", "Matched allowlist: $it")
        }
        for (suffix in domainSuffixes(normalized)) {
            val category = dynamicDomains[suffix]
            if (!category.isNullOrBlank()) {
                return DomainDecision(normalized, category, "blocked", "Matched admin list: $suffix")
            }
        }
        blockedKeywords.sorted().firstOrNull { normalized.contains(it) }?.let {
            return DomainDecision(normalized, "keyword", "blocked", "Matched blocked keyword: $it")
        }
        ADULT_SUFFIXES.firstOrNull { matchesSuffix(normalized, it) }?.let {
            return DomainDecision(normalized, "adult", "blocked", "Matched adult list: $it")
        }
        SOCIAL_SUFFIXES.firstOrNull { matchesSuffix(normalized, it) }?.let {
            return DomainDecision(normalized, "social", "blocked", "Matched social list: $it")
        }
        return DomainDecision(normalized, "unknown", "allowed", "No local blocklist match")
    }

    companion object {
        private val ALLOW_SUFFIXES = setOf(
            "youtube.com", "youtu.be", "youtube-nocookie.com", "youtube.googleapis.com",
            "youtubei.googleapis.com", "googlevideo.com", "ytimg.com", "ggpht.com",
            "gstatic.com", "google.com", "googleapis.com", "msn.com", "bing.com",
            "microsoft.com", "microsoftonline.com", "live.com", "office.com", "windows.com"
        )
        private val SOCIAL_SUFFIXES = setOf(
            "facebook.com", "fb.com", "instagram.com", "cdninstagram.com", "threads.net",
            "tiktok.com", "tiktokcdn.com", "x.com", "twitter.com", "twimg.com",
            "snapchat.com", "reddit.com", "linkedin.com", "pinterest.com"
        )
        private val ADULT_SUFFIXES = setOf(
            "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com", "youporn.com",
            "tube8.com", "spankbang.com", "xhamster.com", "onlyfans.com"
        )
    }
}
