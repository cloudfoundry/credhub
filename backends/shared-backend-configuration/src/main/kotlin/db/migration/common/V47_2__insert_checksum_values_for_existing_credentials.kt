package db.migration.common

import org.apache.commons.codec.digest.DigestUtils
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration
import org.springframework.jdbc.core.JdbcTemplate

class V47_2__insert_checksum_values_for_existing_credentials : SpringJdbcMigration {
    @Throws(Exception::class)
    override fun migrate(jdbcTemplate: JdbcTemplate) {
        val credentials = jdbcTemplate.queryForRowSet("select * from credential")
        while (credentials.next()) {
            val credentialName = credentials.getString("name")
            val credentialValue = DigestUtils.sha256Hex(credentialName)
            jdbcTemplate.update("UPDATE credential SET checksum = ? WHERE name = ?", credentialValue, credentialName)
        }
    }
}
