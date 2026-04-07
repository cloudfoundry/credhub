package org.cloudfoundry.credhub.config

import org.flywaydb.core.api.ResourceProvider
import org.flywaydb.core.api.configuration.FluentConfiguration
import org.flywaydb.core.api.migration.JavaMigration
import org.flywaydb.core.api.resource.LoadableResource
import org.flywaydb.core.internal.scanner.Scanner
import org.springframework.boot.flyway.autoconfigure.FlywayConfigurationCustomizer
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import java.io.Reader
import java.io.StringReader

/**
 * For unit tests against PostgreSQL, strip `CONCURRENTLY` from index DDL in Flyway SQL migrations so
 * migrations do not block on other connections (e.g. Flyway bookkeeping). Production migrations are
 * unchanged on disk; only the in-memory script content is transformed.
 *
 * Every `*.sql` resource is wrapped (Flyway relative paths omit `db/migration/postgres/`); replacements are
 * no-ops for scripts that do not use concurrent index DDL.
 */
@Configuration
@Profile("unit-test-postgres")
class FlywayPostgresTestStripConcurrentlyConfiguration {
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    fun stripConcurrentlyFlywayCustomizer(): FlywayConfigurationCustomizer =
        FlywayConfigurationCustomizer { configuration: FluentConfiguration ->
            val locations = configuration.locations
            val delegateProvider: ResourceProvider =
                Scanner(JavaMigration::class.java, configuration, locations)
            configuration.resourceProvider(
                StripConcurrentlyResourceProvider(delegateProvider),
            )
        }
}

internal fun stripConcurrentIndexDdl(sql: String): String =
    sql
        .replace(CREATE_INDEX_CONCURRENTLY, "CREATE INDEX")
        .replace(DROP_INDEX_CONCURRENTLY, "DROP INDEX")

private val CREATE_INDEX_CONCURRENTLY = Regex("(?i)CREATE\\s+INDEX\\s+CONCURRENTLY\\b")
private val DROP_INDEX_CONCURRENTLY = Regex("(?i)DROP\\s+INDEX\\s+CONCURRENTLY\\b")

private class StripConcurrentlyResourceProvider(
    private val delegate: ResourceProvider,
) : ResourceProvider {
    override fun getResource(name: String): LoadableResource? = delegate.getResource(name)?.let { wrap(it) }

    override fun getResources(
        prefix: String,
        suffixes: Array<String>,
    ): Collection<LoadableResource> = delegate.getResources(prefix, suffixes).map { wrap(it) }

    private fun wrap(resource: LoadableResource): LoadableResource =
        if (resource.filename.endsWith(".sql")) {
            TransformingPostgresSqlResource(resource)
        } else {
            resource
        }
}

private class TransformingPostgresSqlResource(
    private val delegate: LoadableResource,
) : LoadableResource() {
    override fun read(): Reader {
        val original = delegate.read().use { it.readText() }
        val transformed = stripConcurrentIndexDdl(original)
        return StringReader(transformed)
    }

    override fun getAbsolutePath(): String = delegate.absolutePath

    override fun getAbsolutePathOnDisk(): String = delegate.absolutePathOnDisk

    override fun getFilename(): String = delegate.filename

    override fun getRelativePath(): String = delegate.relativePath
}
