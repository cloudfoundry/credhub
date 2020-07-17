package db.migration.common

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import java.sql.Types
import java.util.UUID
import org.cloudfoundry.credhub.utils.UuidUtil
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration
import org.springframework.jdbc.core.JdbcTemplate

class V20_1__set_uuid_in_encryption_key_canary : SpringJdbcMigration {
    @SuppressFBWarnings(value = ["NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"], justification = "The database will definitely exist")
    @Throws(Exception::class)
    override fun migrate(jdbcTemplate: JdbcTemplate) {
        val databaseName = jdbcTemplate
            .dataSource
            ?.getConnection()
            ?.metaData
            ?.databaseProductName
            ?.toLowerCase()
        val types = intArrayOf(Types.VARBINARY, Types.BIGINT)
        val canaryIds = jdbcTemplate.queryForList(
            "select id from encryption_key_canary",
            Long::class.java
        )
        for (id in canaryIds) {
            jdbcTemplate.update(
                "update encryption_key_canary set uuid = ? where id = ?",
                databaseName?.let { getParams(it, id) },
                types
            )
        }
    }

    private fun getParams(databaseName: String, id: Long): Array<Any> {
        val uuid = UUID.randomUUID()
        return if ("postgresql" == databaseName) {
            arrayOf(uuid, id)
        } else {
            arrayOf(UuidUtil.uuidToByteArray(uuid), id)
        }
    }
}
