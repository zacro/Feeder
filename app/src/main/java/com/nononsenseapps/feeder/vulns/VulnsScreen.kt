@file:OptIn(ExperimentalMaterial3Api::class)

package com.nononsenseapps.feeder.vulns

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.nononsenseapps.feeder.R
import com.nononsenseapps.feeder.db.room.VulnAlertRow
import com.nononsenseapps.feeder.db.room.VulnStackItem
import com.nononsenseapps.feeder.ui.compose.theme.SensibleTopAppBar
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

private const val TAB_ALERTS = 0
private const val TAB_STACK = 1

@Composable
fun VulnsScreen(
    viewModel: VulnsViewModel,
    onNavigateUp: () -> Unit,
    onOpenArticle: (Long) -> Unit,
    modifier: Modifier = Modifier,
) {
    val viewState by viewModel.viewState.collectAsStateWithLifecycle()
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
    val snackbarHostState = remember { SnackbarHostState() }
    val coroutineScope = rememberCoroutineScope()

    // Until the user picks a tab: start on "My stack" when nothing is configured yet
    var selectedTab by rememberSaveable { mutableIntStateOf(-1) }
    val tab =
        when {
            selectedTab >= 0 -> selectedTab
            viewState.loaded && viewState.stackItems.isEmpty() -> TAB_STACK
            else -> TAB_ALERTS
        }

    var editing by remember { mutableStateOf<VulnStackItem?>(null) }

    val dismissedText = stringResource(R.string.vuln_dismissed)
    val undoText = stringResource(R.string.vuln_undo)

    Scaffold(
        modifier =
            modifier
                .nestedScroll(scrollBehavior.nestedScrollConnection)
                .windowInsetsPadding(WindowInsets.navigationBars.only(WindowInsetsSides.Horizontal)),
        contentWindowInsets = WindowInsets.statusBars,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            SensibleTopAppBar(
                scrollBehavior = scrollBehavior,
                title = stringResource(R.string.vuln_tab_title),
                navigationIcon = {
                    IconButton(onClick = onNavigateUp) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.go_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = viewModel::requestRescan, enabled = !viewState.rescanning) {
                        Icon(Icons.Default.Refresh, contentDescription = stringResource(R.string.vuln_rescan))
                    }
                    if (tab == TAB_ALERTS) {
                        IconButton(onClick = viewModel::markAllSeen) {
                            Icon(Icons.Default.DoneAll, contentDescription = stringResource(R.string.vuln_mark_all_seen))
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            if (tab == TAB_STACK) {
                ExtendedFloatingActionButton(
                    onClick = { editing = VulnStackItem() },
                    icon = { Icon(Icons.Default.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.vuln_add_stack_item)) },
                )
            }
        },
    ) { padding ->
        Column(
            modifier =
                Modifier
                    .padding(padding)
                    .fillMaxSize(),
        ) {
            val unseen = viewState.alerts.count { !it.seen }
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(
                    selected = tab == TAB_ALERTS,
                    onClick = { selectedTab = TAB_ALERTS },
                    text = {
                        BadgedBox(
                            badge = {
                                if (unseen > 0) {
                                    Badge { Text("$unseen") }
                                }
                            },
                        ) {
                            Text(stringResource(R.string.vuln_alerts))
                        }
                    },
                )
                Tab(
                    selected = tab == TAB_STACK,
                    onClick = { selectedTab = TAB_STACK },
                    text = { Text(stringResource(R.string.vuln_my_stack)) },
                )
            }
            if (viewState.rescanning) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            when (tab) {
                TAB_ALERTS ->
                    AlertsTab(
                        viewState = viewState,
                        onSelectFilter = viewModel::setStackFilter,
                        onToggleHideNotAffected = { viewModel.setHideNotAffected(!viewState.hideNotAffected) },
                        onOpen = { row ->
                            viewModel.markSeen(row.matchId)
                            onOpenArticle(row.feedItemId)
                        },
                        onDismiss = { row ->
                            viewModel.dismiss(row.matchId)
                            coroutineScope.launch {
                                val result =
                                    snackbarHostState.showSnackbar(dismissedText, actionLabel = undoText, withDismissAction = true)
                                if (result == SnackbarResult.ActionPerformed) {
                                    viewModel.undismiss(row.matchId)
                                }
                            }
                        },
                        onGoToStack = { selectedTab = TAB_STACK },
                    )

                else ->
                    StackTab(
                        stackItems = viewState.stackItems,
                        onEdit = { editing = it },
                    )
            }
        }
    }

    editing?.let { item ->
        StackItemDialog(
            initial = item,
            onDismiss = { editing = null },
            onSave = {
                viewModel.saveStackItem(it)
                editing = null
            },
            onDelete =
                if (item.id != 0L) {
                    {
                        viewModel.deleteStackItem(item)
                        editing = null
                    }
                } else {
                    null
                },
        )
    }
}

@Composable
private fun AlertsTab(
    viewState: VulnsViewState,
    onSelectFilter: (Long?) -> Unit,
    onToggleHideNotAffected: () -> Unit,
    onOpen: (VulnAlertRow) -> Unit,
    onDismiss: (VulnAlertRow) -> Unit,
    onGoToStack: () -> Unit,
) {
    if (viewState.loaded && viewState.stackItems.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.vuln_no_stack_title),
            body = stringResource(R.string.vuln_no_stack_body),
            action = stringResource(R.string.vuln_add_stack_item),
            onAction = onGoToStack,
        )
        return
    }

    Column {
        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        ) {
            item(key = "all") {
                FilterChip(
                    selected = viewState.stackFilter == null,
                    onClick = { onSelectFilter(null) },
                    label = { Text(stringResource(R.string.vuln_all)) },
                )
            }
            items(viewState.stackItems, key = { it.id }) { item ->
                FilterChip(
                    selected = viewState.stackFilter == item.id,
                    onClick = { onSelectFilter(if (viewState.stackFilter == item.id) null else item.id) },
                    label = { Text(item.name) },
                )
            }
            if (viewState.stackItems.any { it.version.isNotBlank() }) {
                item(key = "hide") {
                    FilterChip(
                        selected = viewState.hideNotAffected,
                        onClick = onToggleHideNotAffected,
                        label = { Text(stringResource(R.string.vuln_hide_not_affected)) },
                    )
                }
            }
        }

        if (viewState.loaded && viewState.alerts.isEmpty()) {
            Text(
                stringResource(R.string.vuln_no_alerts),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(24.dp),
            )
            return
        }

        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 88.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(viewState.alerts, key = { it.matchId }) { row ->
                AlertCard(
                    row = row,
                    names =
                        if (viewState.stackFilter == null) {
                            viewState.namesPerArticle[row.feedItemId] ?: listOf(row.stackName)
                        } else {
                            listOf(row.stackName)
                        },
                    onClick = { onOpen(row) },
                    onDismiss = { onDismiss(row) },
                )
            }
        }
    }
}

@Composable
private fun AlertCard(
    row: VulnAlertRow,
    names: List<String>,
    onClick: () -> Unit,
    onDismiss: () -> Unit,
) {
    val severity = Severity.fromLevel(row.severity)
    val versionStatus = VersionStatus.fromCode(row.versionStatus)
    val context = LocalContext.current
    val dateFormatter = remember { DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM) }

    Card(
        onClick = onClick,
        colors =
            if (row.seen) {
                CardDefaults.cardColors()
            } else {
                CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest)
            },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp)) {
            Column(
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.weight(1f),
            ) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    val (bg, fg) = severityColors(severity)
                    Pill(
                        text =
                            VulnScanner.severityLabel(context, severity) +
                                (row.cvss?.let { " " + "%.1f".format(it) } ?: ""),
                        background = bg,
                        foreground = fg,
                    )
                    if (row.exploited) {
                        Pill(
                            text = stringResource(R.string.vuln_exploited),
                            background = MaterialTheme.colorScheme.error,
                            foreground = MaterialTheme.colorScheme.onError,
                        )
                    }
                    Text(
                        names.joinToString(", "),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    row.title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = if (row.seen) FontWeight.Normal else FontWeight.Bold,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    buildString {
                        append(row.feedTitle)
                        if (row.sortTime > 0) {
                            append(" · ")
                            append(dateFormatter.format(Instant.ofEpochMilli(row.sortTime).atZone(ZoneId.systemDefault())))
                        }
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val cves = row.cves.split(' ').filter { it.isNotBlank() }
                if (cves.isNotEmpty()) {
                    Text(
                        cves.take(6).joinToString("  ") + if (cves.size > 6) "  +${cves.size - 6}" else "",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                when (versionStatus) {
                    VersionStatus.AFFECTED ->
                        Text(
                            stringResource(R.string.vuln_version_affected),
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error,
                        )

                    VersionStatus.NOT_AFFECTED ->
                        Text(
                            stringResource(R.string.vuln_version_not_affected),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )

                    VersionStatus.UNKNOWN -> Unit
                }
            }
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, contentDescription = stringResource(R.string.vuln_dismiss))
            }
        }
    }
}

@Composable
private fun severityColors(severity: Severity): Pair<Color, Color> {
    val cs = MaterialTheme.colorScheme
    return when (severity) {
        Severity.CRITICAL -> cs.error to cs.onError
        Severity.HIGH -> cs.errorContainer to cs.onErrorContainer
        Severity.MEDIUM -> cs.tertiaryContainer to cs.onTertiaryContainer
        Severity.LOW -> cs.secondaryContainer to cs.onSecondaryContainer
        Severity.UNKNOWN -> cs.surfaceVariant to cs.onSurfaceVariant
    }
}

@Composable
private fun Pill(
    text: String,
    background: Color,
    foreground: Color,
) {
    Surface(color = background, contentColor = foreground, shape = RoundedCornerShape(50)) {
        Text(
            text,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun StackTab(
    stackItems: List<VulnStackItem>,
    onEdit: (VulnStackItem) -> Unit,
) {
    LazyColumn(
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 88.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item(key = "permission") {
            NotificationPermissionCard()
        }
        if (stackItems.isEmpty()) {
            item(key = "empty") {
                EmptyState(
                    title = stringResource(R.string.vuln_no_stack_title),
                    body = stringResource(R.string.vuln_no_stack_body),
                )
            }
        }
        items(stackItems, key = { it.id }) { item ->
            Card(onClick = { onEdit(item) }, modifier = Modifier.fillMaxWidth()) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                    modifier = Modifier.padding(16.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(item.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        if (item.version.isNotBlank()) {
                            Text(
                                item.version,
                                style = MaterialTheme.typography.labelLarge,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                    if (item.aliasList.isNotEmpty()) {
                        Text(
                            item.aliasList.joinToString(", "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Text(
                        stringResource(alertLevelLabel(AlertLevel.fromCode(item.alertLevel))),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun NotificationPermissionCard() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    if (granted) return

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(16.dp),
        ) {
            Text(
                stringResource(R.string.vuln_notification_permission),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = { launcher.launch(Manifest.permission.POST_NOTIFICATIONS) }) {
                Text(stringResource(R.string.vuln_allow))
            }
        }
    }
}

@Composable
private fun EmptyState(
    title: String,
    body: String,
    action: String? = null,
    onAction: () -> Unit = {},
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(32.dp),
    ) {
        Icon(
            Icons.Outlined.Security,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(48.dp),
        )
        Text(title, style = MaterialTheme.typography.titleLarge)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (action != null) {
            Button(onClick = onAction) { Text(action) }
        }
    }
}

private fun alertLevelLabel(level: AlertLevel): Int =
    when (level) {
        AlertLevel.CRITICAL_HIGH -> R.string.vuln_alert_critical_high
        AlertLevel.ALL -> R.string.vuln_alert_all
        AlertLevel.NONE -> R.string.vuln_alert_none
    }

@Composable
private fun StackItemDialog(
    initial: VulnStackItem,
    onDismiss: () -> Unit,
    onSave: (VulnStackItem) -> Unit,
    onDelete: (() -> Unit)?,
) {
    var name by rememberSaveable { mutableStateOf(initial.name) }
    var aliases by rememberSaveable { mutableStateOf(initial.aliasList.joinToString(", ")) }
    var version by rememberSaveable { mutableStateOf(initial.version) }
    var alertLevel by rememberSaveable { mutableIntStateOf(initial.alertLevel) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(
                    if (initial.id == 0L) R.string.vuln_add_stack_item else R.string.vuln_edit_stack_item,
                ),
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.verticalScroll(rememberScrollState()),
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.vuln_name)) },
                    placeholder = { Text(stringResource(R.string.vuln_name_hint)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = aliases,
                    onValueChange = { aliases = it },
                    label = { Text(stringResource(R.string.vuln_aliases)) },
                    placeholder = { Text(stringResource(R.string.vuln_aliases_hint)) },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = version,
                    onValueChange = { version = it },
                    label = { Text(stringResource(R.string.vuln_version)) },
                    placeholder = { Text(stringResource(R.string.vuln_version_hint)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    stringResource(R.string.vuln_matching_help),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(stringResource(R.string.vuln_alert_level), style = MaterialTheme.typography.titleSmall)
                Column(modifier = Modifier.selectableGroup()) {
                    AlertLevel.entries.forEach { level ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .selectable(
                                        selected = alertLevel == level.code,
                                        onClick = { alertLevel = level.code },
                                        role = Role.RadioButton,
                                    ).padding(vertical = 4.dp),
                        ) {
                            RadioButton(selected = alertLevel == level.code, onClick = null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(alertLevelLabel(level)), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = name.isNotBlank(),
                onClick = {
                    onSave(
                        initial.copy(
                            name = name,
                            aliases = aliases,
                            version = version,
                            alertLevel = alertLevel,
                        ),
                    )
                },
            ) {
                Text(stringResource(R.string.vuln_save))
            }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) {
                        Text(stringResource(R.string.vuln_delete), color = MaterialTheme.colorScheme.error)
                    }
                }
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.vuln_cancel))
                }
            }
        },
    )
}

@Composable
fun VulnsDrawerItem(
    unseenCount: Int,
    onClick: () -> Unit,
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
        modifier =
            Modifier
                .clickable(onClick = onClick)
                .padding(end = 16.dp, top = 2.dp, bottom = 2.dp)
                .fillMaxWidth()
                .height(48.dp),
    ) {
        Spacer(Modifier.width(16.dp))
        Icon(
            Icons.Outlined.Security,
            contentDescription = null,
            modifier = Modifier.size(24.dp),
        )
        Spacer(Modifier.width(12.dp))
        Text(
            stringResource(R.string.vuln_tab_title),
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.weight(1f),
        )
        if (unseenCount > 0) {
            Badge(containerColor = MaterialTheme.colorScheme.error) {
                Text("$unseenCount")
            }
        }
    }
}
