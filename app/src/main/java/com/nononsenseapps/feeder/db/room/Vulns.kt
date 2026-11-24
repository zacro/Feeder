package com.nononsenseapps.feeder.db.room

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import com.nononsenseapps.feeder.db.COL_ID
import com.nononsenseapps.feeder.db.FEED_ITEMS_TABLE_NAME
import kotlinx.coroutines.flow.Flow

const val VULN_STACK_ITEMS_TABLE_NAME = "vuln_stack_items"
const val VULN_MATCHES_TABLE_NAME = "vuln_matches"

/**
 * A piece of the user's tech stack, e.g. "Jira" with aliases "Atlassian Jira", "jira-software"
 * and an optional version.
 */
@Entity(tableName = VULN_STACK_ITEMS_TABLE_NAME)
data class VulnStackItem(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = ID_UNSET,
    @ColumnInfo(name = "name") val name: String = "",
    /** Newline separated */
    @ColumnInfo(name = "aliases") val aliases: String = "",
    @ColumnInfo(name = "version") val version: String = "",
    /** See [com.nononsenseapps.feeder.vulns.AlertLevel] */
    @ColumnInfo(name = "alert_level") val alertLevel: Int = 0,
) {
    val aliasList: List<String>
        get() = aliases.split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }
}

@Entity(
    tableName = VULN_MATCHES_TABLE_NAME,
    indices = [
        Index(value = ["feed_item_id", "stack_item_id"], unique = true),
        Index(value = ["stack_item_id"]),
    ],
    foreignKeys = [
        ForeignKey(
            entity = FeedItem::class,
            parentColumns = [COL_ID],
            childColumns = ["feed_item_id"],
            onDelete = ForeignKey.CASCADE,
        ),
        ForeignKey(
            entity = VulnStackItem::class,
            parentColumns = ["id"],
            childColumns = ["stack_item_id"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class VulnMatchEntity(
    @PrimaryKey(autoGenerate = true)
    @ColumnInfo(name = "id")
    val id: Long = ID_UNSET,
    @ColumnInfo(name = "feed_item_id") val feedItemId: Long,
    @ColumnInfo(name = "stack_item_id") val stackItemId: Long,
    /** See [com.nononsenseapps.feeder.vulns.Severity.level] */
    @ColumnInfo(name = "severity") val severity: Int = 0,
    @ColumnInfo(name = "cvss") val cvss: Double? = null,
    /** Space separated CVE ids */
    @ColumnInfo(name = "cves") val cves: String = "",
    @ColumnInfo(name = "exploited") val exploited: Boolean = false,
    /** See [com.nononsenseapps.feeder.vulns.VersionStatus.code] */
    @ColumnInfo(name = "version_status") val versionStatus: Int = 0,
    @ColumnInfo(name = "matched_term") val matchedTerm: String = "",
    @ColumnInfo(name = "notified") val notified: Boolean = false,
    @ColumnInfo(name = "seen") val seen: Boolean = false,
    @ColumnInfo(name = "dismissed") val dismissed: Boolean = false,
    /** Epoch millis */
    @ColumnInfo(name = "matched_at") val matchedAt: Long = 0,
)

/** Row for the Vulnerabilities tab. */
data class VulnAlertRow(
    @ColumnInfo(name = "match_id") val matchId: Long,
    @ColumnInfo(name = "feed_item_id") val feedItemId: Long,
    @ColumnInfo(name = "stack_item_id") val stackItemId: Long,
    @ColumnInfo(name = "stack_name") val stackName: String,
    @ColumnInfo(name = "severity") val severity: Int,
    @ColumnInfo(name = "cvss") val cvss: Double?,
    @ColumnInfo(name = "cves") val cves: String,
    @ColumnInfo(name = "exploited") val exploited: Boolean,
    @ColumnInfo(name = "version_status") val versionStatus: Int,
    @ColumnInfo(name = "matched_term") val matchedTerm: String,
    @ColumnInfo(name = "seen") val seen: Boolean,
    @ColumnInfo(name = "title") val title: String,
    @ColumnInfo(name = "snippet") val snippet: String,
    @ColumnInfo(name = "link") val link: String?,
    @ColumnInfo(name = "sort_time") val sortTime: Long,
    @ColumnInfo(name = "feed_title") val feedTitle: String,
)

/** Minimal article data needed to (re)scan stored articles. */
data class VulnScanCandidate(
    @ColumnInfo(name = "id") val id: Long,
    @ColumnInfo(name = "plain_title") val plainTitle: String,
    @ColumnInfo(name = "plain_snippet") val plainSnippet: String,
)

@Dao
interface VulnDao {
    // ---- Stack ----

    @Query("SELECT * FROM $VULN_STACK_ITEMS_TABLE_NAME ORDER BY name COLLATE NOCASE")
    fun observeStackItems(): Flow<List<VulnStackItem>>

    @Query("SELECT * FROM $VULN_STACK_ITEMS_TABLE_NAME")
    suspend fun getStackItems(): List<VulnStackItem>

    @Insert
    suspend fun insertStackItem(item: VulnStackItem): Long

    @Update
    suspend fun updateStackItem(item: VulnStackItem)

    @Delete
    suspend fun deleteStackItem(item: VulnStackItem)

    // ---- Matches ----

    @Query("SELECT * FROM $VULN_MATCHES_TABLE_NAME WHERE feed_item_id = :feedItemId")
    suspend fun getMatchesForItem(feedItemId: Long): List<VulnMatchEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertMatch(match: VulnMatchEntity): Long

    @Update
    suspend fun updateMatch(match: VulnMatchEntity)

    @Query("DELETE FROM $VULN_MATCHES_TABLE_NAME WHERE id IN (:ids)")
    suspend fun deleteMatches(ids: List<Long>)

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET notified = 1 WHERE id IN (:ids)")
    suspend fun setNotified(ids: List<Long>)

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET seen = 1 WHERE id = :id")
    suspend fun markSeen(id: Long)

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET seen = 1 WHERE feed_item_id = :feedItemId")
    suspend fun markSeenForItem(feedItemId: Long)

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET seen = 1 WHERE seen = 0")
    suspend fun markAllSeen()

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET dismissed = 1, seen = 1 WHERE id = :id")
    suspend fun dismiss(id: Long)

    @Query("UPDATE $VULN_MATCHES_TABLE_NAME SET dismissed = 0 WHERE id = :id")
    suspend fun undismiss(id: Long)

    @Query(
        """
        SELECT m.id AS match_id, m.feed_item_id, m.stack_item_id, s.name AS stack_name,
               m.severity, m.cvss, m.cves, m.exploited, m.version_status, m.matched_term, m.seen,
               fi.plain_title AS title, fi.plain_snippet AS snippet, fi.link AS link,
               fi.primary_sort_time AS sort_time,
               COALESCE(NULLIF(f.custom_title, ''), f.title) AS feed_title
        FROM $VULN_MATCHES_TABLE_NAME m
        JOIN $VULN_STACK_ITEMS_TABLE_NAME s ON s.id = m.stack_item_id
        JOIN $FEED_ITEMS_TABLE_NAME fi ON fi.id = m.feed_item_id
        JOIN feeds f ON f.id = fi.feed_id
        WHERE m.dismissed = 0 AND fi.block_time IS NULL
        ORDER BY fi.primary_sort_time DESC
        """,
    )
    fun observeAlerts(): Flow<List<VulnAlertRow>>

    @Query(
        """
        SELECT COUNT(DISTINCT m.feed_item_id) FROM $VULN_MATCHES_TABLE_NAME m
        JOIN $FEED_ITEMS_TABLE_NAME fi ON fi.id = m.feed_item_id
        WHERE m.seen = 0 AND m.dismissed = 0 AND fi.block_time IS NULL
        """,
    )
    fun observeUnseenCount(): Flow<Int>

    @Query(
        """
        SELECT id, plain_title, plain_snippet FROM $FEED_ITEMS_TABLE_NAME
        WHERE block_time IS NULL
        ORDER BY id
        LIMIT :limit OFFSET :offset
        """,
    )
    suspend fun getScanCandidates(
        limit: Int,
        offset: Int,
    ): List<VulnScanCandidate>

    @Query("SELECT id, plain_title, plain_snippet FROM $FEED_ITEMS_TABLE_NAME WHERE id IN (:ids)")
    suspend fun getScanCandidatesByIds(ids: List<Long>): List<VulnScanCandidate>

    /**
     * Replace the stored matches of one article with [matches], keeping the user's
     * seen/dismissed/notified flags for matches that already existed.
     *
     * @return the matches that are new (not previously stored), with their assigned ids
     */
    @Transaction
    suspend fun replaceMatchesForItem(
        feedItemId: Long,
        matches: List<VulnMatchEntity>,
    ): List<VulnMatchEntity> {
        val existing = getMatchesForItem(feedItemId).associateBy { it.stackItemId }
        val keep = matches.map { it.stackItemId }.toSet()
        val toDelete = existing.values.filter { it.stackItemId !in keep }.map { it.id }
        if (toDelete.isNotEmpty()) deleteMatches(toDelete)

        val created = mutableListOf<VulnMatchEntity>()
        for (m in matches) {
            val old = existing[m.stackItemId]
            if (old == null) {
                val id = insertMatch(m)
                if (id > 0) created += m.copy(id = id)
            } else {
                updateMatch(
                    m.copy(
                        id = old.id,
                        notified = old.notified || m.notified,
                        seen = old.seen,
                        dismissed = old.dismissed,
                        matchedAt = old.matchedAt,
                    ),
                )
            }
        }
        return created
    }
}
