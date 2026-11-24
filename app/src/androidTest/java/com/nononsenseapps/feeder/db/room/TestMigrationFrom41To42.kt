package com.nononsenseapps.feeder.db.room

import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import com.nononsenseapps.feeder.FeederApplication
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kodein.di.DI
import org.kodein.di.DIAware
import org.kodein.di.android.closestDI
import kotlin.test.assertEquals

@RunWith(AndroidJUnit4::class)
@LargeTest
class TestMigrationFrom41To42 : DIAware {
    private val dbName = "testDb"
    private val feederApplication: FeederApplication = ApplicationProvider.getApplicationContext()
    override val di: DI by closestDI(feederApplication)

    @Rule
    @JvmField
    val testHelper: MigrationTestHelper =
        MigrationTestHelper(
            InstrumentationRegistry.getInstrumentation(),
            AppDatabase::class.java,
            emptyList(),
            FrameworkSQLiteOpenHelperFactory(),
        )

    @Test
    fun migrate() {
        @Suppress("SimpleRedundantLet")
        testHelper.createDatabase(dbName, FROM_VERSION).let { oldDB ->
            oldDB.execSQL(
                """
                INSERT INTO feeds(id, title, url, custom_title, tag, notify, image_url, last_sync, response_hash, fulltext_by_default, open_articles_with, alternate_id, currently_syncing, when_modified, site_fetched, skip_duplicates, retry_after, summarize_on_open, fetch_og_images, block_rules, allow_rules, trust_all_certificates)
                VALUES(1, 'feed', 'http://url', '', '', 0, null, 0, 666, 0, '', 0, 0, 0, 0, 0, 0, 0, 0, '', '', 0)
                """.trimIndent(),
            )
        }
        val db =
            testHelper.runMigrationsAndValidate(
                dbName,
                TO_VERSION,
                true,
                MIGRATION_41_42,
            )

        db.execSQL(
            """
            INSERT INTO vuln_stack_items(id, name, aliases, version, alert_level)
            VALUES(1, 'Jira', 'Atlassian Jira', '9.12.1', 0)
            """.trimIndent(),
        )

        db
            .query(
                """
                select name, aliases, version, alert_level from vuln_stack_items
                """.trimIndent(),
            ).use {
                assert(it.count == 1)
                assert(it.moveToFirst())
                assertEquals("Jira", it.getString(0))
                assertEquals("Atlassian Jira", it.getString(1))
                assertEquals("9.12.1", it.getString(2))
                assertEquals(0, it.getInt(3))
            }

        db
            .query(
                """
                select count(*) from vuln_matches
                """.trimIndent(),
            ).use {
                assert(it.moveToFirst())
                assertEquals(0, it.getInt(0))
            }
    }

    companion object {
        private const val FROM_VERSION = 41
        private const val TO_VERSION = 42
    }
}
