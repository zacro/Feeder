package com.nononsenseapps.feeder.vulns

import com.nononsenseapps.feeder.db.room.VulnStackItem
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * File format for exporting/importing the tech stack. Deliberately simple and versioned so
 * future builds can still read old backups.
 */
@Serializable
data class StackBackup(
    val format: String = FORMAT,
    val version: Int = 1,
    val items: List<StackBackupItem> = emptyList(),
) {
    companion object {
        const val FORMAT = "feeder-stackwatch-stack"
        const val MIME_TYPE = "application/json"
        const val DEFAULT_FILE_NAME = "stackwatch-stack.json"

        private val json =
            Json {
                ignoreUnknownKeys = true
                prettyPrint = true
                encodeDefaults = true
            }

        fun encode(items: List<VulnStackItem>): String =
            json.encodeToString(
                serializer(),
                StackBackup(
                    items =
                        items.map {
                            StackBackupItem(
                                name = it.name,
                                aliases = it.aliasList,
                                version = it.version,
                                alertLevel = AlertLevel.fromCode(it.alertLevel).name,
                            )
                        },
                ),
            )

        /** @throws IllegalArgumentException when the text is not a stack backup */
        fun decode(text: String): List<VulnStackItem> {
            val backup = json.decodeFromString(serializer(), text)
            require(backup.format == FORMAT) { "Not a StackWatch stack backup" }
            return backup.items
                .filter { it.name.isNotBlank() }
                .map { item ->
                    VulnStackItem(
                        name = item.name.trim(),
                        aliases =
                            item.aliases
                                .map { it.trim() }
                                .filter { it.isNotEmpty() }
                                .joinToString("\n"),
                        version = item.version.trim(),
                        alertLevel =
                            (AlertLevel.entries.firstOrNull { it.name == item.alertLevel } ?: AlertLevel.CRITICAL_HIGH).code,
                    )
                }
        }

        /**
         * Merge imported items into the existing stack: items with the same name (ignoring case)
         * are updated, new ones are added, nothing is deleted.
         *
         * @return items to update (keeping existing ids) and items to insert
         */
        fun merge(
            existing: List<VulnStackItem>,
            imported: List<VulnStackItem>,
        ): Pair<List<VulnStackItem>, List<VulnStackItem>> {
            val byName = existing.associateBy { it.name.lowercase() }
            val toUpdate = mutableListOf<VulnStackItem>()
            val toInsert = mutableListOf<VulnStackItem>()
            for (item in imported.distinctBy { it.name.lowercase() }) {
                val current = byName[item.name.lowercase()]
                if (current == null) {
                    toInsert += item
                } else if (current.copy(id = 0) != item) {
                    toUpdate += item.copy(id = current.id)
                }
            }
            return toUpdate to toInsert
        }
    }
}

@Serializable
data class StackBackupItem(
    val name: String,
    val aliases: List<String> = emptyList(),
    val version: String = "",
    /** [AlertLevel] name */
    val alertLevel: String = AlertLevel.CRITICAL_HIGH.name,
)
