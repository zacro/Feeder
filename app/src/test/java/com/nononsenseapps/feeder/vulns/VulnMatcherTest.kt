package com.nononsenseapps.feeder.vulns

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class VulnMatcherTest {
    private val jira = StackItemSpec(id = 1, name = "Jira", aliases = listOf("Atlassian Jira", "jira-software"))
    private val nodejs = StackItemSpec(id = 2, name = "Node.js", aliases = listOf("nodejs"))
    private val springBoot = StackItemSpec(id = 3, name = "Spring Boot")

    @Test
    fun matchesNameCaseInsensitiveInTitle() {
        val m = VulnMatcher.analyze("Critical vulnerability in JIRA allows RCE", "", listOf(jira))
        assertEquals(1, m.size)
        assertEquals(1L, m[0].stackItemId)
        assertEquals(Severity.CRITICAL, m[0].severity)
    }

    @Test
    fun matchesAliasInBody() {
        val m =
            VulnMatcher.analyze(
                "Security advisory",
                "A flaw in jira software (CVE-2024-21683) allows authenticated RCE.",
                listOf(jira),
            )
        assertEquals(1, m.size)
        assertEquals(listOf("CVE-2024-21683"), m[0].cves)
    }

    @Test
    fun requiresWholeWords() {
        val m = VulnMatcher.analyze("Jirafy vulnerability disclosed", "CVE-2024-0001 in jirafy", listOf(jira))
        assertTrue(m.isEmpty())
    }

    @Test
    fun punctuationInTermsIsLiteral() {
        val m = VulnMatcher.analyze("Node.js security release fixes high severity issues", "", listOf(nodejs))
        assertEquals(1, m.size)
        assertEquals(Severity.HIGH, m[0].severity)
        assertTrue(VulnMatcher.analyze("Nodexjs vulnerability", "", listOf(nodejs)).isEmpty())
    }

    @Test
    fun multiWordTermsTolerateHyphensAndSpaces() {
        val m = VulnMatcher.analyze("spring-boot actuator exploit", "", listOf(springBoot))
        assertEquals(1, m.size)
    }

    @Test
    fun ignoresNonSecurityArticles() {
        val m = VulnMatcher.analyze("Jira 10 released with new dashboards", "Atlassian ships a redesigned board.", listOf(jira))
        assertTrue(m.isEmpty())
    }

    @Test
    fun noStackNoMatches() {
        assertTrue(VulnMatcher.analyze("Critical Jira CVE-2024-1", "", emptyList()).isEmpty())
    }

    @Test
    fun cvssScoreSetsSeverity() {
        val (sev, score) = VulnMatcher.extractSeverity("The issue has a CVSS v3.1 base score of 9.8.")
        assertEquals(Severity.CRITICAL, sev)
        assertEquals(9.8, score)
        assertEquals(Severity.HIGH, VulnMatcher.extractSeverity("CVSS: 7.5").first)
        assertEquals(Severity.MEDIUM, VulnMatcher.extractSeverity("rated 5.3 out of 10").first)
        assertEquals(Severity.HIGH, VulnMatcher.extractSeverity("CVSS score 8.1 (High)").first)
    }

    @Test
    fun cvssVersionNumberIsNotTheScore() {
        val (_, score) = VulnMatcher.extractSeverity("CVSS 3.1 base score: 6.1")
        assertEquals(6.1, score)
    }

    @Test
    fun severityWords() {
        assertEquals(Severity.HIGH, VulnMatcher.extractSeverity("Severity: High").first)
        assertEquals(Severity.CRITICAL, VulnMatcher.extractSeverity("rated critical by the vendor").first)
        assertEquals(Severity.MEDIUM, VulnMatcher.extractSeverity("a moderate-severity bug").first)
        assertEquals(Severity.UNKNOWN, VulnMatcher.extractSeverity("a bug was found").first)
    }

    @Test
    fun exploitedBumpsToHigh() {
        val m = VulnMatcher.analyze("Jira flaw actively exploited in attacks", "", listOf(jira))
        assertEquals(1, m.size)
        assertTrue(m[0].exploited)
        assertEquals(Severity.HIGH, m[0].severity)
    }

    @Test
    fun notifyRules() {
        val base =
            VulnMatch(1, "Jira", Severity.MEDIUM, null, emptyList(), exploited = false, versionStatus = VersionStatus.UNKNOWN)
        assertFalse(VulnMatcher.shouldNotify(base, AlertLevel.CRITICAL_HIGH))
        assertTrue(VulnMatcher.shouldNotify(base, AlertLevel.ALL))
        assertTrue(VulnMatcher.shouldNotify(base.copy(severity = Severity.HIGH), AlertLevel.CRITICAL_HIGH))
        assertTrue(VulnMatcher.shouldNotify(base.copy(exploited = true), AlertLevel.CRITICAL_HIGH))
        assertFalse(VulnMatcher.shouldNotify(base.copy(severity = Severity.CRITICAL), AlertLevel.NONE))
        assertFalse(
            VulnMatcher.shouldNotify(
                base.copy(severity = Severity.CRITICAL, versionStatus = VersionStatus.NOT_AFFECTED),
                AlertLevel.ALL,
            ),
        )
    }

    // --- Version awareness ---

    private fun status(
        version: String,
        text: String,
        item: StackItemSpec = jira,
    ): VersionStatus {
        val m = VulnMatcher.analyze(text, "", listOf(item.copy(version = version)))
        assertEquals(1, m.size, "expected a match for: $text")
        return m[0].versionStatus
    }

    @Test
    fun versionBefore() {
        val t = "Jira Data Center vulnerability CVE-2024-1 affects versions before 9.12.3"
        assertEquals(VersionStatus.AFFECTED, status("9.12.1", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("9.12.3", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("10.0.0", t))
    }

    @Test
    fun versionFixedOnMultipleBranches() {
        val t = "Jira vulnerability CVE-2024-1 fixed in 9.12.3 and 10.1.2"
        assertEquals(VersionStatus.AFFECTED, status("9.12.1", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("9.13.0", t))
        assertEquals(VersionStatus.AFFECTED, status("10.0.5", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("10.1.2", t))
        assertEquals(VersionStatus.AFFECTED, status("8.20.0", t))
    }

    @Test
    fun versionExplicitRange() {
        val t = "Jira RCE vulnerability affects Jira 9.0.0 through 9.4.14"
        assertEquals(VersionStatus.AFFECTED, status("9.4.0", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("9.4.15", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("8.22.0", t))
    }

    @Test
    fun versionAndEarlier() {
        val t = "Jira vulnerability: 9.4.1 and earlier are affected"
        assertEquals(VersionStatus.AFFECTED, status("9.4.1", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("9.4.2", t))
    }

    @Test
    fun versionWildcard() {
        val t = "Jira vulnerability affects all 8.x releases"
        assertEquals(VersionStatus.AFFECTED, status("8.20.1", t))
        assertEquals(VersionStatus.NOT_AFFECTED, status("9.0.0", t))
    }

    @Test
    fun versionUnknownWhenNothingParseable() {
        assertEquals(VersionStatus.UNKNOWN, status("9.12.1", "Critical Jira vulnerability CVE-2024-1 disclosed"))
    }

    @Test
    fun versionNotSetIsUnknown() {
        val m = VulnMatcher.analyze("Jira vulnerability before 9.12.3", "", listOf(jira))
        assertEquals(VersionStatus.UNKNOWN, m[0].versionStatus)
    }

    @Test
    fun datesAreNotVersions() {
        assertEquals(VersionStatus.UNKNOWN, status("9.12.1", "Jira vulnerability CVE-2024-1 disclosed before 2024-12"))
    }

    @Test
    fun versionParsingAndCompare() {
        val a = VersionAnalyzer.Version.parse("v9.12")!!
        val b = VersionAnalyzer.Version.parse("9.12.0")!!
        assertEquals(0, a.compareTo(b))
        assertTrue(VersionAnalyzer.Version.parse("9.12.10")!! > VersionAnalyzer.Version.parse("9.12.9")!!)
        assertNull(VersionAnalyzer.Version.parse("abc"))
    }

    @Test
    fun multipleStackItemsMatchIndependently() {
        val m =
            VulnMatcher.analyze(
                "Patch Tuesday: critical flaws",
                "Security updates for Jira and Node.js, CVE-2024-11111 and CVE-2024-22222.",
                listOf(jira, nodejs, springBoot),
            )
        assertEquals(setOf(1L, 2L), m.map { it.stackItemId }.toSet())
        assertEquals(listOf("CVE-2024-11111", "CVE-2024-22222"), m[0].cves)
    }
}
