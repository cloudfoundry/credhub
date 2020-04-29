package db.migration.common

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings
import java.sql.Types
import org.cloudfoundry.credhub.utils.UuidUtil
import org.flywaydb.core.api.migration.BaseJavaMigration
import org.flywaydb.core.api.migration.Context
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.SingleConnectionDataSource

class V44_2__migrate_encypted_values_to_encryped_value_table : BaseJavaMigration() {
    @SuppressFBWarnings(value = ["NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE"], justification = "The database will definitely exist")
    @Throws(Exception::class)
    override fun migrate(context: Context) {
        val jdbcTemplate = JdbcTemplate(SingleConnectionDataSource(context.connection, true))
        val databaseName = jdbcTemplate
            .dataSource
            ?.getConnection()
            ?.metaData
            ?.databaseProductName
            ?.toLowerCase()
        val credentialsWithEncryptedValues = jdbcTemplate
            .queryForList("select uuid from credential_version where encrypted_value is not null",
                Any::class.java)
        for (credentialUuid in credentialsWithEncryptedValues) {
            val encryptedValueUuid = UuidUtil.makeUuid(databaseName)
            jdbcTemplate.update(
                "insert into encrypted_value (" +
                    "uuid, " +
                    "encryption_key_uuid, " +
                    "encrypted_value, " +
                    "nonce, " +
                    "updated_at" +
                    ")" +
                    "select " +
                    "?, " +
                    "encryption_key_uuid, " +
                    "encrypted_value, " +
                    "nonce, " +
                    "updated_at " +
                    "from credential_version " +
                    "where uuid = ?", arrayOf(encryptedValueUuid, credentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
            jdbcTemplate.update(
                "update credential_version " +
                    "set encrypted_value_uuid = ? " +
                    "where uuid = ?", arrayOf(encryptedValueUuid, credentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
        }
        val passwordsWithEncryptedValues = jdbcTemplate.queryForList(
            "select uuid from password_credential where encrypted_generation_parameters is not null",
            Any::class.java)
        for (passwordCredentialUuid in passwordsWithEncryptedValues) {
            val encryptedValueUuid = UuidUtil.makeUuid(databaseName)
            jdbcTemplate.update(
                "insert into encrypted_value (" +
                    "uuid, " +
                    "encryption_key_uuid, " +
                    "encrypted_value, " +
                    "nonce, " +
                    "updated_at" +
                    ")" +
                    "select " +
                    "?, " +
                    "credential_version.encryption_key_uuid, " +
                    "password_credential.encrypted_generation_parameters, " +
                    "password_credential.parameters_nonce, " +
                    "credential_version.updated_at " +
                    "from credential_version, password_credential " +
                    "where credential_version.uuid = password_credential.uuid and " +
                    "credential_version.uuid = ?;", arrayOf(encryptedValueUuid, passwordCredentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
            jdbcTemplate.update(
                "update password_credential " +
                    "set password_parameters_uuid = ? " +
                    "where uuid = ?", arrayOf(encryptedValueUuid, passwordCredentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
        }
        val usersWithEncryptedValues = jdbcTemplate.queryForList(
            "select uuid from user_credential where encrypted_generation_parameters is not null",
            Any::class.java)
        for (userCredentialUuid in usersWithEncryptedValues) {
            val encryptedValueUuid = UuidUtil.makeUuid(databaseName)
            jdbcTemplate.update(
                "insert into encrypted_value (" +
                    "uuid, " +
                    "encryption_key_uuid, " +
                    "encrypted_value, " +
                    "nonce, " +
                    "updated_at" +
                    ")" +
                    "select " +
                    "?, " +
                    "credential_version.encryption_key_uuid, " +
                    "user_credential.encrypted_generation_parameters, " +
                    "user_credential.parameters_nonce, " +
                    "credential_version.updated_at " +
                    "from credential_version, user_credential " +
                    "where credential_version.uuid = user_credential.uuid and " +
                    "credential_version.uuid = ?;", arrayOf(encryptedValueUuid, userCredentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
            jdbcTemplate.update(
                "update user_credential " +
                    "set password_parameters_uuid = ? " +
                    "where uuid = ?", arrayOf(encryptedValueUuid, userCredentialUuid), intArrayOf(Types.VARBINARY, Types.VARBINARY))
        }
    }
}
