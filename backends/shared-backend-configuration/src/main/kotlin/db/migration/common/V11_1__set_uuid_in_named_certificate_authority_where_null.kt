package db.migration.common

import org.flywaydb.core.api.migration.BaseJavaMigration
import java.util.UUID
import org.flywaydb.core.api.migration.Context
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.SingleConnectionDataSource

class V11_1__set_uuid_in_named_certificate_authority_where_null : BaseJavaMigration() {
    @Throws(Exception::class)
    override fun migrate(context: Context) {
        val jdbcTemplate = JdbcTemplate(SingleConnectionDataSource(context.connection, true))
        val nullUuidRecords = jdbcTemplate.queryForList(
            "select id from named_certificate_authority where uuid is null",
            Long::class.java
        )
        for (record in nullUuidRecords) {
            jdbcTemplate.update(
                "update named_certificate_authority set uuid = ? where id = ?",
                UUID.randomUUID().toString(), record
            )
        }
    }
}
