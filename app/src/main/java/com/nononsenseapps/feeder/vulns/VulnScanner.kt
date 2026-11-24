package com.nononsenseapps.feeder.vulns

import android.Manifest
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.nononsenseapps.feeder.R
import com.nononsenseapps.feeder.blob.blobInputStream
import com.nononsenseapps.feeder.db.room.VulnDao
import com.nononsenseapps.feeder.db.room.VulnMatchEntity
import com.nononsenseapps.feeder.db.room.VulnStackItem
import com.nononsenseapps.feeder.ui.MainActivity
import com.nononsenseapps.feeder.ui.text.HtmlToPlainTextConverter
import com.nononsenseapps.feeder.util.DEEP_LINK_BASE_URI
import com.nononsenseapps.feeder.util.FilePathProvider
import com.nononsenseapps.feeder.util.logDebug
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.kodein.di.DI
import org.kodein.di.DIAware
import org.kodein.di.instance
import java.time.Instant

/** An article as seen right after a sync, before the HTML is stripped. */
data class ScanInput(
    val feedItemId: Long,
    val title: String,
    val html: String,
)

/**
 * Connects [VulnMatcher] to the database and to Android notifications.
 *
 *  - [scanSyncedItems] is called by the RSS sync for new/changed articles. New matches that pass
 *    the stack item's alert level produce a high priority notification.
 *  - [rescanAll] re-evaluates every stored article, e.g. after the stack was edited. It never
 *    notifies, to avoid a flood of alerts for old articles.
 */
class VulnScanner(
    override val di: DI,
) : DIAware {
    private val vulnDao: VulnDao by instance()
    private val filePathProvider: FilePathProvider by instance()
    private val application: Application by instance()

    private val mutex = Mutex()

    private fun VulnStackItem.toSpec() =
        StackItemSpec(
            id = id,
            name = name,
            aliases = aliasList,
            version = version,
            alertLevel = AlertLevel.fromCode(alertLevel),
        )

    suspend fun scanSyncedItems(items: List<ScanInput>) {
        if (items.isEmpty()) return
        try {
            withContext(Dispatchers.Default) {
                mutex.withLock {
                    val stack = vulnDao.getStackItems().map { it.toSpec() }
                    if (stack.isEmpty()) return@withLock
                    val stackById = stack.associateBy { it.id }
                    val toNotify = mutableListOf<Pair<VulnMatchEntity, ScanInput>>()

                    for (item in items) {
                        val body = htmlToText(item.html)
                        val matches = VulnMatcher.analyze(item.title, body, stack)
                        val created =
                            vulnDao.replaceMatchesForItem(
                                item.feedItemId,
                                matches.map { it.toEntity(item.feedItemId, notified = false) },
                            )
                        for (entity in created) {
                            val spec = stackById[entity.stackItemId] ?: continue
                            val match = matches.first { it.stackItemId == entity.stackItemId }
                            if (VulnMatcher.shouldNotify(match, spec.alertLevel)) {
                                toNotify += entity to item
                            }
                        }
                    }

                    if (toNotify.isNotEmpty()) {
                        postNotifications(toNotify, stackById)
                        vulnDao.setNotified(toNotify.map { it.first.id })
                    }
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e(LOG_TAG, "Failed to scan synced items", e)
        }
    }

    suspend fun rescanAll() {
        try {
            withContext(Dispatchers.IO) {
                mutex.withLock {
                    val stack = vulnDao.getStackItems().map { it.toSpec() }
                    var offset = 0
                    var count = 0
                    while (true) {
                        val page = vulnDao.getScanCandidates(limit = PAGE_SIZE, offset = offset)
                        if (page.isEmpty()) break
                        for (candidate in page) {
                            val matches =
                                if (stack.isEmpty()) {
                                    emptyList()
                                } else {
                                    val body =
                                        readArticleText(candidate.id)
                                            ?: candidate.plainSnippet
                                    VulnMatcher.analyze(candidate.plainTitle, body, stack)
                                }
                            // Rescans never notify: store them as already notified
                            vulnDao.replaceMatchesForItem(
                                candidate.id,
                                matches.map { it.toEntity(candidate.id, notified = true) },
                            )
                            count += matches.size
                        }
                        offset += page.size
                    }
                    logDebug(LOG_TAG, "Rescanned $offset articles, $count matches")
                }
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e(LOG_TAG, "Failed to rescan articles", e)
        }
    }

    private fun readArticleText(itemId: Long): String? =
        try {
            blobInputStream(itemId, filePathProvider.articleDir)
                .bufferedReader()
                .use { it.readText() }
                .let { htmlToText(it) }
        } catch (e: Exception) {
            null
        }

    private fun htmlToText(html: String): String =
        if (html.isBlank()) {
            ""
        } else {
            try {
                HtmlToPlainTextConverter().convert(html)
            } catch (e: Exception) {
                html
            }
        }

    private fun VulnMatch.toEntity(
        feedItemId: Long,
        notified: Boolean,
    ) = VulnMatchEntity(
        feedItemId = feedItemId,
        stackItemId = stackItemId,
        severity = severity.level,
        cvss = cvssScore,
        cves = cves.joinToString(" "),
        exploited = exploited,
        versionStatus = versionStatus.code,
        matchedTerm = matchedTerm,
        notified = notified,
        matchedAt = Instant.now().toEpochMilli(),
    )

    private fun postNotifications(
        toNotify: List<Pair<VulnMatchEntity, ScanInput>>,
        stackById: Map<Long, StackItemSpec>,
    ) {
        val context: Context = application
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            logDebug(LOG_TAG, "No notification permission, skipping ${toNotify.size} vuln alerts")
            return
        }
        createChannel(context)
        val nm = NotificationManagerCompat.from(context)

        // One notification per article, listing every stack item it hits
        toNotify
            .groupBy { it.first.feedItemId }
            .forEach { (feedItemId, entries) ->
                val item = entries.first().second
                val worst = entries.maxBy { it.first.severity }.first
                val severity = Severity.fromLevel(worst.severity)
                val names = entries.mapNotNull { stackById[it.first.stackItemId]?.name }.distinct()
                val cves = worst.cves.split(' ').filter { it.isNotBlank() }

                val header =
                    buildString {
                        append(severityLabel(context, severity))
                        if (worst.exploited) append(" · ").append(context.getString(R.string.vuln_exploited))
                        append(" · ").append(names.joinToString(", "))
                    }
                val text =
                    buildString {
                        append(item.title)
                        if (cves.isNotEmpty()) append("\n").append(cves.take(5).joinToString(", "))
                        if (worst.versionStatus == VersionStatus.AFFECTED.code) {
                            append("\n").append(context.getString(R.string.vuln_version_affected))
                        }
                    }

                val contentIntent =
                    PendingIntent.getActivity(
                        context,
                        (NOTIFICATION_ID_BASE + feedItemId).toInt(),
                        Intent(
                            Intent.ACTION_VIEW,
                            "$DEEP_LINK_BASE_URI/article/$feedItemId".toUri(),
                            context,
                            MainActivity::class.java,
                        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    )
                val tabIntent =
                    PendingIntent.getActivity(
                        context,
                        (NOTIFICATION_ID_BASE - feedItemId).toInt(),
                        Intent(
                            Intent.ACTION_VIEW,
                            "$DEEP_LINK_BASE_URI/vulns".toUri(),
                            context,
                            MainActivity::class.java,
                        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                    )

                val notification =
                    NotificationCompat
                        .Builder(context, CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_stat_f)
                        .setContentTitle(header)
                        .setContentText(item.title)
                        .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                        .setContentIntent(contentIntent)
                        .addAction(0, context.getString(R.string.vuln_tab_title), tabIntent)
                        .setAutoCancel(true)
                        .setGroup(GROUP)
                        .setCategory(NotificationCompat.CATEGORY_ALARM)
                        .setPriority(NotificationCompat.PRIORITY_HIGH)
                        .build()
                try {
                    nm.notify((NOTIFICATION_ID_BASE + feedItemId).toInt(), notification)
                } catch (e: SecurityException) {
                    Log.w(LOG_TAG, "Notification permission revoked", e)
                }
            }
    }

    companion object {
        private const val LOG_TAG = "FEEDER_VULNS"
        private const val PAGE_SIZE = 200
        const val CHANNEL_ID = "feederVulnAlerts"
        private const val GROUP = "com.nononsenseapps.feeder.VULNS"

        // Keeps vuln notification ids away from the regular article notification ids
        private const val NOTIFICATION_ID_BASE = 1_000_000_000L

        fun createChannel(context: Context) {
            val channel =
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.vuln_channel_name),
                    NotificationManager.IMPORTANCE_HIGH,
                )
            channel.description = context.getString(R.string.vuln_channel_description)
            context.getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }

        fun severityLabel(
            context: Context,
            severity: Severity,
        ): String =
            context.getString(
                when (severity) {
                    Severity.CRITICAL -> R.string.vuln_severity_critical
                    Severity.HIGH -> R.string.vuln_severity_high
                    Severity.MEDIUM -> R.string.vuln_severity_medium
                    Severity.LOW -> R.string.vuln_severity_low
                    Severity.UNKNOWN -> R.string.vuln_severity_unknown
                },
            )
    }
}
