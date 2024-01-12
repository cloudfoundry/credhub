package db.migration.common

import org.cloudfoundry.credhub.CryptSaltFactory
import org.cloudfoundry.credhub.utils.UuidUtil
import org.flywaydb.core.api.migration.BaseJavaMigration
import org.flywaydb.core.api.migration.Context
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.SingleConnectionDataSource
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.sql.ResultSet
import java.util.UUID

class V41_1__set_salt_in_existing_user_credentials : BaseJavaMigration() {
    @Throws(Exception::class)
    override fun migrate(context: Context) {
        val jdbcTemplate = JdbcTemplate(SingleConnectionDataSource(context.connection, true))
        val databaseName = jdbcTemplate
            .dataSource
            ?.getConnection()
            ?.metaData
            ?.databaseProductName
            ?.lowercase()
        val saltFactory = CryptSaltFactory()
        val uuids = jdbcTemplate.query("select uuid from user_credential") { rowSet: ResultSet, _: Int ->
            val uuidBytes = rowSet.getBytes("uuid")
            if ("postgresql" == databaseName) {
                return@query UUID.fromString(String(uuidBytes, StandardCharsets.UTF_8))
            } else {
                val byteBuffer = ByteBuffer.wrap(uuidBytes)
                return@query UUID(byteBuffer.long, byteBuffer.long)
            }
        }
        for (uuid in uuids) {
            val salt = saltFactory.generateSalt()
            jdbcTemplate.update(
                "update user_credential set salt = ? where uuid = ?",
                *arrayOf(salt, databaseName?.let { getUuidParam(it, uuid) })
            )
        }
    }

    private fun getUuidParam(databaseName: String, uuid: UUID): Any {
        return if ("postgresql" == databaseName) {
            uuid
        } else {
            UuidUtil.uuidToByteArray(uuid)
        }
    }
}
