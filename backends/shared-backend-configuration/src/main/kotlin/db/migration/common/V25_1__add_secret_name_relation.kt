package db.migration.common

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import java.sql.Types
import org.cloudfoundry.credhub.utils.UuidUtil
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration
import org.springframework.jdbc.core.JdbcTemplate

class V25_1__add_secret_name_relation : SpringJdbcMigration {
    @SuppressFBWarnings(value = ["NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"], justification = "The database will definitely exist")
    @Throws(Exception::class)
    override fun migrate(jdbcTemplate: JdbcTemplate) {
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
                "insert into secret_name (uuid, name) values (?, ?)", arrayOf(UuidUtil.makeUuid(databaseName), name), intArrayOf(Types.VARBINARY, Types.VARCHAR))
        }
    }
}
