package com.nononsenseapps.feeder.vulns

/**
 * Pure-Kotlin matching engine for the Vulnerabilities tab. No Android dependencies so it can be
 * unit tested on the JVM.
 *
 * An article becomes a match for a stack item when:
 *  1. the item's name or one of its aliases occurs as a whole word (case-insensitive,
 *     spaces/hyphens/underscores interchangeable) in the title or body, AND
 *  2. the article looks security related (CVE id, or vulnerability vocabulary).
 *
 * For every match it also extracts CVE ids, a severity (CVSS score or wording), whether the
 * issue is said to be exploited in the wild, and - if the user entered a version - a best-effort
 * guess whether that version is affected.
 */
enum class Severity(
    val level: Int,
) {
    UNKNOWN(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4),
    ;

    companion object {
        fun fromLevel(level: Int): Severity = entries.firstOrNull { it.level == level } ?: UNKNOWN

        fun fromCvss(score: Double): Severity =
            when {
                score >= 9.0 -> CRITICAL
                score >= 7.0 -> HIGH
                score >= 4.0 -> MEDIUM
                score > 0.0 -> LOW
                else -> UNKNOWN
            }
    }
}

enum class VersionStatus(
    val code: Int,
) {
    /** No version configured, or nothing parseable in the text. */
    UNKNOWN(0),
    AFFECTED(1),
    NOT_AFFECTED(2),
    ;

    companion object {
        fun fromCode(code: Int): VersionStatus = entries.firstOrNull { it.code == code } ?: UNKNOWN
    }
}

enum class AlertLevel(
    val code: Int,
) {
    /** Notify only for critical/high (or exploited-in-the-wild) issues. Default. */
    CRITICAL_HIGH(0),

    /** Notify for every match. */
    ALL(1),

    /** Show in the tab, never notify. */
    NONE(2),
    ;

    companion object {
        fun fromCode(code: Int): AlertLevel = entries.firstOrNull { it.code == code } ?: CRITICAL_HIGH
    }
}

data class StackItemSpec(
    val id: Long,
    val name: String,
    val aliases: List<String> = emptyList(),
    val version: String = "",
    val alertLevel: AlertLevel = AlertLevel.CRITICAL_HIGH,
) {
    val terms: List<String>
        get() = (listOf(name) + aliases).map { it.trim() }.filter { it.isNotEmpty() }.distinctBy { it.lowercase() }
}

data class VulnMatch(
    val stackItemId: Long,
    val matchedTerm: String,
    val severity: Severity,
    val cvssScore: Double?,
    val cves: List<String>,
    val exploited: Boolean,
    val versionStatus: VersionStatus,
)

object VulnMatcher {
    private val cveRegex = Regex("""\bCVE-(\d{4})-(\d{4,7})\b""", RegexOption.IGNORE_CASE)

    private val vulnVocabulary =
        Regex(
            listOf(
                """vulnerabilit(?:y|ies)""",
                """vuln(?:s)?""",
                """exploit(?:s|ed|able|ation)?""",
                """zero[- ]?days?""",
                """0[- ]?days?""",
                """security (?:advisory|advisories|bulletin|update|fix|patch|flaw|issue|bug|release)s?""",
                """advisory""",
                """remote code execution""",
                """\bRCE\b""",
                """code injection""",
                """command injection""",
                """sql injection""",
                """\bSQLi\b""",
                """cross[- ]site (?:scripting|request forgery)""",
                """\bXSS\b""",
                """\bCSRF\b""",
                """\bSSRF\b""",
                """server[- ]side request forgery""",
                """path traversal""",
                """directory traversal""",
                """(?:authentication|auth) bypass""",
                """privilege escalation""",
                """denial[- ]of[- ]service""",
                """insecure deserialization""",
                """deserialization""",
                """arbitrary (?:code|file|command)""",
                """information disclosure""",
                """memory corruption""",
                """buffer overflow""",
                """use[- ]after[- ]free""",
                """\bCVSS""",
                """\bGHSA-""",
                """known exploited""",
                """backdoor(?:ed)?""",
                """compromised""",
                """malicious (?:package|version|code)""",
                """supply[- ]chain attack""",
            ).joinToString("|", prefix = "(?:", postfix = ")"),
            RegexOption.IGNORE_CASE,
        )

    private val cvssRegex =
        Regex(
            """CVSS(?:\s*v?\s*[234](?:\.\d)?)?(?:\s*(?:base|overall))?(?:\s*score)?(?:\s*(?:of|:|=|is|-|–))?\s*(\d{1,2}(?:\.\d)?)(?!\.\d)""",
            RegexOption.IGNORE_CASE,
        )

    // e.g. "9.8 CVSS", "scored 9.8 out of 10", "(CVSS: 9.8)"
    private val scoreOutOfTenRegex =
        Regex("""\b(\d{1,2}\.\d)\s*(?:/\s*10(?:\.0)?|out of 10)\b""", RegexOption.IGNORE_CASE)

    private val severityWordRegexes: List<Pair<Regex, Severity>> =
        listOf(
            "critical" to Severity.CRITICAL,
            "high" to Severity.HIGH,
            "important" to Severity.HIGH,
            "medium" to Severity.MEDIUM,
            "moderate" to Severity.MEDIUM,
            "low" to Severity.LOW,
        ).flatMap { (word, sev) ->
            listOf(
                Regex("""\b$word[- ](?:severity|risk|impact|rated)\b""", RegexOption.IGNORE_CASE) to sev,
                Regex("""\bseverity(?: level| rating)?\s*[:=]?\s*(?:is\s+|of\s+)?$word\b""", RegexOption.IGNORE_CASE) to sev,
                Regex("""\brated\s+(?:as\s+)?$word\b""", RegexOption.IGNORE_CASE) to sev,
            )
        } +
            listOf(
                Regex(
                    """\bcritical\s+(?:\w+\s+){0,2}(?:vulnerabilit(?:y|ies)|flaws?|bugs?|security (?:update|fix|patch)|RCE|remote code execution|zero[- ]?day|patch(?:es)?|advisor(?:y|ies))\b""",
                    RegexOption.IGNORE_CASE,
                ) to Severity.CRITICAL,
                Regex(
                    """\bhigh[- ]severity\b|\bseverity\s*:\s*high\b""",
                    RegexOption.IGNORE_CASE,
                ) to Severity.HIGH,
            )

    private val exploitedRegex =
        Regex(
            """actively exploited|exploited in the wild|in[- ]the[- ]wild|under (?:active )?exploitation|known exploited|zero[- ]?day|0[- ]?day|being exploited|exploitation (?:has been )?(?:observed|detected|confirmed)""",
            RegexOption.IGNORE_CASE,
        )

    private val termRegexCache = HashMap<String, Regex>()

    /** Compile a whole-word, case-insensitive regex for a term. Spaces/hyphens/underscores are interchangeable. */
    internal fun termRegex(term: String): Regex =
        synchronized(termRegexCache) {
            termRegexCache.getOrPut(term.lowercase()) {
                val parts = term.trim().split(Regex("""[\s\-_]+""")).filter { it.isNotEmpty() }
                val body = parts.joinToString("""[\s\-_]*""") { Regex.escape(it) }
                Regex("""(?<![\p{L}\p{N}])$body(?![\p{L}\p{N}])""", RegexOption.IGNORE_CASE)
            }
        }

    fun isSecurityRelated(text: String): Boolean = cveRegex.containsMatchIn(text) || vulnVocabulary.containsMatchIn(text)

    fun extractCves(text: String): List<String> =
        cveRegex
            .findAll(text)
            .map { "CVE-${it.groupValues[1]}-${it.groupValues[2]}" }
            .distinct()
            .toList()

    fun extractCvss(text: String): Double? {
        val scores =
            (cvssRegex.findAll(text).map { it.groupValues[1] } + scoreOutOfTenRegex.findAll(text).map { it.groupValues[1] })
                .mapNotNull { it.toDoubleOrNull() }
                .filter { it > 0.0 && it <= 10.0 }
                .toList()
        return scores.maxOrNull()
    }

    fun extractSeverity(text: String): Pair<Severity, Double?> {
        val cvss = extractCvss(text)
        var best = cvss?.let { Severity.fromCvss(it) } ?: Severity.UNKNOWN
        for ((regex, sev) in severityWordRegexes) {
            if (sev.level > best.level && regex.containsMatchIn(text)) {
                best = sev
            }
        }
        return best to cvss
    }

    fun isExploited(text: String): Boolean = exploitedRegex.containsMatchIn(text)

    /**
     * Analyse an article against the user's stack.
     *
     * @param title article title (plain text)
     * @param body article body (plain text, HTML already stripped)
     */
    fun analyze(
        title: String,
        body: String,
        stack: List<StackItemSpec>,
    ): List<VulnMatch> {
        if (stack.isEmpty()) return emptyList()
        val text = "$title\n$body"
        if (!isSecurityRelated(text)) return emptyList()

        var severityAndCvss: Pair<Severity, Double?>? = null
        var cves: List<String>? = null
        var exploited: Boolean? = null

        return stack.mapNotNull { item ->
            // Prefer a title hit, then the body
            val hits =
                item.terms.flatMap { term ->
                    termRegex(term).findAll(text).map { term to it.range }.toList()
                }
            if (hits.isEmpty()) return@mapNotNull null

            val (sev, cvss) = severityAndCvss ?: extractSeverity(text).also { severityAndCvss = it }
            val itemCves = cves ?: extractCves(text).also { cves = it }
            val itemExploited = exploited ?: isExploited(text).also { exploited = it }

            val versionStatus =
                if (item.version.isBlank()) {
                    VersionStatus.UNKNOWN
                } else {
                    VersionAnalyzer.status(
                        userVersion = item.version,
                        text = text,
                        termRanges = hits.map { it.second },
                    )
                }

            VulnMatch(
                stackItemId = item.id,
                matchedTerm = hits.first().first,
                severity = if (itemExploited && sev.level < Severity.HIGH.level) Severity.HIGH else sev,
                cvssScore = cvss,
                cves = itemCves,
                exploited = itemExploited,
                versionStatus = versionStatus,
            )
        }
    }

    fun shouldNotify(
        match: VulnMatch,
        alertLevel: AlertLevel,
    ): Boolean {
        if (match.versionStatus == VersionStatus.NOT_AFFECTED) return false
        return when (alertLevel) {
            AlertLevel.NONE -> false
            AlertLevel.ALL -> true
            AlertLevel.CRITICAL_HIGH -> match.exploited || match.severity.level >= Severity.HIGH.level
        }
    }
}

/**
 * Best-effort extraction of affected version ranges from free text near a product mention.
 *
 * Understood phrasings (in a window after each mention of the product):
 *  - "before 9.12.3", "prior to 9.12.3", "earlier than", "< 9.12.3", "older than"
 *  - "fixed in 9.12.3", "patched in", "upgrade to 9.12.3", "update to", "resolved in"
 *  - "through 9.12.1", "up to 9.12.1", "<= 9.12.1", "9.12.1 and earlier/below/prior/older"
 *  - "9.0.0 through/to/- 9.12.1" ranges, "9.x" wildcards, "versions 9.4.0, 9.4.1" lists
 *
 * Result is AFFECTED if any range contains the user's version, NOT_AFFECTED only if ranges
 * were found and none of them contains it, otherwise UNKNOWN.
 */
object VersionAnalyzer {
    private const val WINDOW = 400
    private const val V = """v?(\d+(?:\.\d+){0,3}(?:\.x)?)"""

    private val rangeRegex =
        Regex("""$V\s*(?:through|thru|to|until|-|–|—)\s*(?:version\s*)?$V""", RegexOption.IGNORE_CASE)
    private val beforeRegex =
        Regex(
            """(?:before|prior to|earlier than|older than|lower than|below|<)\s*(?:versions?\s*)?$V((?:\s*(?:,|and|or)\s*v?\d+(?:\.\d+){1,3})*)""",
            RegexOption.IGNORE_CASE,
        )
    private val throughRegex =
        Regex(
            """(?:up to(?: and including)?|through|<=|≤|up until)\s*(?:versions?\s*)?$V((?:\s*(?:,|and|or)\s*v?\d+(?:\.\d+){1,3})*)""",
            RegexOption.IGNORE_CASE,
        )
    private val andEarlierRegex =
        Regex("""$V\s*(?:and|or)\s*(?:earlier|below|prior|older|lower)""", RegexOption.IGNORE_CASE)
    private val fixedRegex =
        Regex(
            """(?:fixed|patched|resolved|addressed|remediated)\s+in\s+(?:versions?\s*)?$V((?:\s*(?:,|and|or)\s*v?\d+(?:\.\d+){1,3})*)|(?:upgrade|update)\s+to\s+(?:versions?\s*)?$V((?:\s*(?:,|and|or)\s*v?\d+(?:\.\d+){1,3})*)""",
            RegexOption.IGNORE_CASE,
        )
    private val wildcardRegex = Regex("""\b(\d+(?:\.\d+)*)\.x\b""", RegexOption.IGNORE_CASE)
    private val listVersionRegex = Regex("""v?(\d+(?:\.\d+){1,3})""")

    data class Version(
        val parts: List<Int>,
    ) : Comparable<Version> {
        override fun compareTo(other: Version): Int {
            val n = maxOf(parts.size, other.parts.size)
            for (i in 0 until n) {
                val a = parts.getOrElse(i) { 0 }
                val b = other.parts.getOrElse(i) { 0 }
                if (a != b) return a.compareTo(b)
            }
            return 0
        }

        val major: Int get() = parts.firstOrNull() ?: 0

        override fun toString(): String = parts.joinToString(".")

        companion object {
            fun parse(s: String): Version? {
                val cleaned =
                    s
                        .trim()
                        .removePrefix("v")
                        .removePrefix("V")
                        .removeSuffix(".x")
                        .removeSuffix(".X")
                val m = Regex("""^(\d+(?:\.\d+)*)""").find(cleaned) ?: return null
                return Version(m.groupValues[1].split('.').mapNotNull { it.toIntOrNull() })
            }
        }
    }

    private sealed interface Constraint {
        fun contains(v: Version): Boolean?
    }

    /** lower <= v <= upper (either bound optional), upperExclusive for "before". */
    private data class Range(
        val lower: Version?,
        val upper: Version?,
        val upperExclusive: Boolean,
    ) : Constraint {
        override fun contains(v: Version): Boolean {
            if (lower != null && v < lower) return false
            if (upper != null) {
                val c = v.compareTo(upper)
                if (upperExclusive && c >= 0) return false
                if (!upperExclusive && c > 0) return false
            }
            return true
        }
    }

    /** Wildcard like 9.x: same prefix. */
    private data class Prefix(
        val prefix: List<Int>,
    ) : Constraint {
        override fun contains(v: Version): Boolean = v.parts.size >= prefix.size && v.parts.take(prefix.size) == prefix
    }

    /**
     * A set of fixed versions on possibly several release branches ("fixed in 9.12.3 and 10.1.2").
     * Affected if v is below the fix on its own branch.
     */
    private data class FixedIn(
        val fixes: List<Version>,
        /** true: versions are the last affected ones ("through 9.12.1"); false: first fixed ones. */
        val inclusive: Boolean = false,
    ) : Constraint {
        override fun contains(v: Version): Boolean? {
            val sorted = fixes.sorted()
            if (sorted.isEmpty()) return null
            // Choose fix on the same branch: longest shared prefix, ties broken by smallest fix >= v
            val sameMajor = sorted.filter { it.major == v.major }
            if (sameMajor.isNotEmpty()) {
                val sameMinor = sameMajor.filter { it.parts.getOrNull(1) == v.parts.getOrNull(1) }
                val candidates = sameMinor.ifEmpty { sameMajor }
                val fix = candidates.firstOrNull { it >= v } ?: return false
                return if (inclusive) v <= fix else v < fix
            }
            if (v < sorted.first()) return true
            if (v > sorted.last()) return false
            return null
        }
    }

    fun status(
        userVersion: String,
        text: String,
        termRanges: List<IntRange>,
    ): VersionStatus {
        val v = Version.parse(userVersion) ?: return VersionStatus.UNKNOWN
        val constraints = mutableListOf<Constraint>()
        // Merge windows
        val windows =
            termRanges
                .map { it.first to minOf(text.length, it.last + 1 + WINDOW) }
                .sortedBy { it.first }
        val merged = mutableListOf<Pair<Int, Int>>()
        for (w in windows) {
            val last = merged.lastOrNull()
            if (last != null && w.first <= last.second) {
                merged[merged.lastIndex] = last.first to maxOf(last.second, w.second)
            } else {
                merged.add(w)
            }
        }
        for ((start, end) in merged) {
            constraints += parseConstraints(text.substring(start, end))
        }
        if (constraints.isEmpty()) return VersionStatus.UNKNOWN

        val results = constraints.map { it.contains(v) }
        return when {
            results.any { it == true } -> VersionStatus.AFFECTED
            results.all { it == false } -> VersionStatus.NOT_AFFECTED
            else -> VersionStatus.UNKNOWN
        }
    }

    private fun parseConstraints(window: String): List<Constraint> {
        val out = mutableListOf<Constraint>()
        val consumed = mutableListOf<IntRange>()
        val fixedVersions = mutableListOf<Version>()
        val lastAffectedVersions = mutableListOf<Version>()

        fun free(r: IntRange) = consumed.none { it.first <= r.last && r.first <= it.last }

        fun versionList(
            first: String,
            rest: String,
        ): List<Version> =
            (listOf(first) + listVersionRegex.findAll(rest).map { it.groupValues[1] })
                .filter { it.contains('.') }
                .mapNotNull { Version.parse(it) }

        // Explicit ranges first: "9.0.0 through 9.12.1"
        for (m in rangeRegex.findAll(window)) {
            val lowS = m.groupValues[1]
            val highS = m.groupValues[2]
            // Avoid treating dates or single numbers ("2023-12") as version ranges
            if (!lowS.contains('.') || !highS.contains('.')) continue
            val low = Version.parse(lowS) ?: continue
            val high = Version.parse(highS) ?: continue
            if (high < low) continue
            val upper = if (highS.endsWith(".x", ignoreCase = true)) Version(high.parts + Int.MAX_VALUE) else high
            out += Range(low, upper, upperExclusive = false)
            consumed += m.range
        }
        for (m in fixedRegex.findAll(window)) {
            if (!free(m.range)) continue
            val first = m.groups[1]?.value ?: m.groups[3]?.value ?: continue
            val rest = m.groups[2]?.value ?: m.groups[4]?.value ?: ""
            val versions = versionList(first, rest)
            if (versions.isNotEmpty()) {
                fixedVersions += versions
                consumed += m.range
            }
        }
        for (m in beforeRegex.findAll(window)) {
            if (!free(m.range)) continue
            val versions = versionList(m.groupValues[1], m.groupValues[2])
            if (versions.isNotEmpty()) {
                fixedVersions += versions
                consumed += m.range
            }
        }
        for (m in throughRegex.findAll(window)) {
            if (!free(m.range)) continue
            val versions = versionList(m.groupValues[1], m.groupValues[2])
            if (versions.isNotEmpty()) {
                lastAffectedVersions += versions
                consumed += m.range
            }
        }
        for (m in andEarlierRegex.findAll(window)) {
            if (!free(m.range)) continue
            val s = m.groupValues[1]
            if (!s.contains('.')) continue
            lastAffectedVersions += Version.parse(s) ?: continue
            consumed += m.range
        }
        for (m in wildcardRegex.findAll(window)) {
            if (!free(m.range)) continue
            val prefix = m.groupValues[1].split('.').mapNotNull { it.toIntOrNull() }
            if (prefix.isNotEmpty()) {
                out += Prefix(prefix)
                consumed += m.range
            }
        }
        if (fixedVersions.isNotEmpty()) out += FixedIn(fixedVersions.distinct(), inclusive = false)
        if (lastAffectedVersions.isNotEmpty()) out += FixedIn(lastAffectedVersions.distinct(), inclusive = true)
        return out
    }
}
