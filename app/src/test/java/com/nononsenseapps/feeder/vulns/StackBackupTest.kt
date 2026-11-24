package com.nononsenseapps.feeder.vulns

import com.nononsenseapps.feeder.db.room.VulnStackItem
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StackBackupTest {
    private val jira =
        VulnStackItem(
            id = 7,
            name = "Jira",
            aliases = "Atlassian Jira\njira-software",
            version = "9.12.1",
            alertLevel = AlertLevel.ALL.code,
        )

    @Test
    fun roundTrip() {
        val decoded = StackBackup.decode(StackBackup.encode(listOf(jira)))
        assertEquals(listOf(jira.copy(id = 0)), decoded)
    }

    @Test
    fun exportHasNoDatabaseIds() {
        assertTrue("\"id\"" !in StackBackup.encode(listOf(jira)))
    }

    @Test
    fun rejectsOtherJson() {
        assertFailsWith<IllegalArgumentException> {
            StackBackup.decode("""{"format":"something-else","items":[]}""")
        }
    }

    @Test
    fun unknownAlertLevelFallsBackToDefault() {
        val items =
            StackBackup.decode(
                """{"format":"feeder-stackwatch-stack","items":[{"name":"Nginx","alertLevel":"LOUD","future":1}]}""",
            )
        assertEquals(AlertLevel.CRITICAL_HIGH.code, items.single().alertLevel)
    }

    @Test
    fun mergeUpdatesByNameIgnoringCaseAndAddsNew() {
        val existing = listOf(jira, VulnStackItem(id = 8, name = "Nginx"))
        val imported =
            listOf(
                jira.copy(id = 0, name = "JIRA", version = "10.0.0"),
                // unchanged
                VulnStackItem(name = "Nginx"),
                VulnStackItem(name = "Node.js"),
            )
        val (toUpdate, toInsert) = StackBackup.merge(existing, imported)
        assertEquals(listOf(7L), toUpdate.map { it.id })
        assertEquals("10.0.0", toUpdate.single().version)
        assertEquals(listOf("Node.js"), toInsert.map { it.name })
    }
}
