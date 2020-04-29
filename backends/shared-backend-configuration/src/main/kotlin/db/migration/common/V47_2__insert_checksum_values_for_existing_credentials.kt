package db.migration.common

import org.apache.commons.codec.digest.DigestUtils
import org.flywaydb.core.api.migration.BaseJavaMigration
import org.flywaydb.core.api.migration.Context
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.SingleConnectionDataSource

class V47_2__insert_checksum_values_for_existing_credentials : BaseJavaMigration() {
    @Throws(Exception::class)
    override fun migrate(context: Context) {
        val jdbcTemplate = JdbcTemplate(SingleConnectionDataSource(context.connection, true))
        val credentials = jdbcTemplate.queryForRowSet("select * from credential")
        while (credentials.next()) {
            val credentialName = credentials.getString("name")
            val credentialValue = DigestUtils.sha256Hex(credentialName)
            jdbcTemplate.update("UPDATE credential SET checksum = ? WHERE name = ?", credentialValue, credentialName)
        }
    }
}
