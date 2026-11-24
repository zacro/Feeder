package com.nononsenseapps.feeder.vulns

import android.app.Application
import android.net.Uri
import android.util.Log
import androidx.lifecycle.viewModelScope
import com.nononsenseapps.feeder.ApplicationCoroutineScope
import com.nononsenseapps.feeder.R
import com.nononsenseapps.feeder.base.DIAwareViewModel
import com.nononsenseapps.feeder.db.room.VulnAlertRow
import com.nononsenseapps.feeder.db.room.VulnDao
import com.nononsenseapps.feeder.db.room.VulnStackItem
import com.nononsenseapps.feeder.util.ToastMaker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kodein.di.DI
import org.kodein.di.instance

data class VulnsViewState(
    val stackItems: List<VulnStackItem> = emptyList(),
    val alerts: List<VulnAlertRow> = emptyList(),
    /** null = all stack items */
    val stackFilter: Long? = null,
    val hideNotAffected: Boolean = false,
    val rescanning: Boolean = false,
    val loaded: Boolean = false,
    /** All stack item names hitting each article (feed item id -> names). */
    val namesPerArticle: Map<Long, List<String>> = emptyMap(),
)

class VulnsViewModel(
    di: DI,
) : DIAwareViewModel(di) {
    private val vulnDao: VulnDao by instance()
    private val vulnScanner: VulnScanner by instance()
    private val applicationCoroutineScope: ApplicationCoroutineScope by instance()
    private val toastMaker: ToastMaker by instance()

    private val stackFilter = MutableStateFlow<Long?>(null)
    private val hideNotAffected = MutableStateFlow(false)
    private val rescanning = MutableStateFlow(false)

    val viewState: StateFlow<VulnsViewState> =
        combine(
            vulnDao.observeStackItems(),
            vulnDao.observeAlerts(),
            stackFilter,
            hideNotAffected,
            rescanning,
        ) { stack, alerts, filter, hide, scanning ->
            // Drop a filter that points at a deleted stack item
            val activeFilter = filter?.takeIf { id -> stack.any { it.id == id } }
            VulnsViewState(
                stackItems = stack,
                alerts =
                    alerts
                        .asSequence()
                        .filter { activeFilter == null || it.stackItemId == activeFilter }
                        .filter { !hide || it.versionStatus != VersionStatus.NOT_AFFECTED.code }
                        // Several stack items can hit the same article; show it once in "All"
                        .distinctBy { if (activeFilter == null) it.feedItemId else it.matchId }
                        .toList(),
                stackFilter = activeFilter,
                hideNotAffected = hide,
                rescanning = scanning,
                loaded = true,
                namesPerArticle =
                    alerts
                        .groupBy({ it.feedItemId }, { it.stackName })
                        .mapValues { (_, names) -> names.distinct() },
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), VulnsViewState())

    fun setStackFilter(id: Long?) {
        stackFilter.value = id
    }

    fun setHideNotAffected(value: Boolean) {
        hideNotAffected.value = value
    }

    fun saveStackItem(item: VulnStackItem) {
        val cleaned =
            item.copy(
                name = item.name.trim(),
                aliases =
                    item.aliases
                        .split(',', '\n')
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                        .joinToString("\n"),
                version = item.version.trim(),
            )
        if (cleaned.name.isEmpty()) return
        applicationCoroutineScope.launch {
            if (cleaned.id == 0L) {
                vulnDao.insertStackItem(cleaned)
            } else {
                vulnDao.updateStackItem(cleaned)
            }
            rescan()
        }
    }

    fun deleteStackItem(item: VulnStackItem) {
        applicationCoroutineScope.launch {
            // Matches are removed through the foreign key cascade
            vulnDao.deleteStackItem(item)
        }
    }

    fun dismiss(matchId: Long) {
        applicationCoroutineScope.launch { vulnDao.dismiss(matchId) }
    }

    fun undismiss(matchId: Long) {
        applicationCoroutineScope.launch { vulnDao.undismiss(matchId) }
    }

    fun markSeen(matchId: Long) {
        applicationCoroutineScope.launch { vulnDao.markSeen(matchId) }
    }

    fun markAllSeen() {
        applicationCoroutineScope.launch { vulnDao.markAllSeen() }
    }

    fun exportStack(uri: Uri) {
        applicationCoroutineScope.launch {
            try {
                val text = StackBackup.encode(vulnDao.getStackItems())
                withContext(Dispatchers.IO) {
                    getApplication<Application>()
                        .contentResolver
                        .openOutputStream(uri, "wt")
                        ?.bufferedWriter()
                        ?.use { it.write(text) }
                        ?: error("Could not open file")
                }
                toastMaker.makeToast(R.string.vuln_export_done)
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.e(LOG_TAG, "Stack export failed", e)
                toastMaker.makeToast(R.string.vuln_export_failed)
            }
        }
    }

    fun importStack(uri: Uri) {
        applicationCoroutineScope.launch {
            try {
                val text =
                    withContext(Dispatchers.IO) {
                        getApplication<Application>()
                            .contentResolver
                            .openInputStream(uri)
                            ?.bufferedReader()
                            ?.use { it.readText() }
                            ?: error("Could not open file")
                    }
                val imported = StackBackup.decode(text)
                val (toUpdate, toInsert) = StackBackup.merge(vulnDao.getStackItems(), imported)
                toUpdate.forEach { vulnDao.updateStackItem(it) }
                toInsert.forEach { vulnDao.insertStackItem(it) }
                toastMaker.makeToast(R.string.vuln_import_done)
                if (toUpdate.isNotEmpty() || toInsert.isNotEmpty()) {
                    rescan()
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.e(LOG_TAG, "Stack import failed", e)
                toastMaker.makeToast(R.string.vuln_import_failed)
            }
        }
    }

    fun requestRescan() {
        applicationCoroutineScope.launch { rescan() }
    }

    private suspend fun rescan() {
        rescanning.value = true
        try {
            vulnScanner.rescanAll()
        } finally {
            rescanning.value = false
        }
    }
}

private const val LOG_TAG = "FEEDER_VULNS_VM"
