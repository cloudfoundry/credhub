package db.migration.common

import org.cloudfoundry.credhub.utils.UuidUtil
import org.flywaydb.core.api.migration.BaseJavaMigration
import org.flywaydb.core.api.migration.Context
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.SingleConnectionDataSource
import java.sql.Types

class V25_1__add_secret_name_relation : BaseJavaMigration() {
    @Throws(Exception::class)
    override fun migrate(context: Context) {
        val jdbcTemplate = JdbcTemplate(SingleConnectionDataSource(context.connection, true))
        val databaseName = jdbcTemplate
            .dataSource
            ?.getConnection()
            ?.metaData
            ?.databaseProductName
            ?.toLowerCase()
        val names = jdbcTemplate
            .queryForList("select distinct(name) from named_secret", String::class.java)
        for (name in names) {
            jdbcTemplate.update(
                "insert into secret_name (uuid, name) values (?, ?)", arrayOf(UuidUtil.makeUuid(databaseName), name), intArrayOf(Types.VARBINARY, Types.VARCHAR)
            )
        }
    }
}
