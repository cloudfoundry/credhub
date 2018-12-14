package db.migration.common;

import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;

import static org.cloudfoundry.credhub.util.UuidUtil.makeUuid;

@SuppressWarnings("unused")
public class V44_2__migrate_encypted_values_to_encryped_value_table implements SpringJdbcMigration {

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "The database will definitely exist"
  )
  @Override
  public void migrate(final JdbcTemplate jdbcTemplate) throws SQLException {
    final String databaseName = jdbcTemplate
      .getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    final List<Object> credentialsWithEncryptedValues = jdbcTemplate
        .queryForList("select uuid from credential_version where encrypted_value is not null",
            Object.class);

    for (final Object credentialUuid : credentialsWithEncryptedValues) {
      final Object encryptedValueUuid = makeUuid(databaseName);
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
              "where uuid = ?",
          new Object[]{encryptedValueUuid, credentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
      jdbcTemplate.update(
          "update credential_version " +
              "set encrypted_value_uuid = ? " +
              "where uuid = ?",
          new Object[]{encryptedValueUuid, credentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
    }

    final List<Object> passwordsWithEncryptedValues = jdbcTemplate.queryForList(
        "select uuid from password_credential where encrypted_generation_parameters is not null",
        Object.class);

    for (final Object passwordCredentialUuid : passwordsWithEncryptedValues) {
      final Object encryptedValueUuid = makeUuid(databaseName);
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
              "credential_version.uuid = ?;",
          new Object[]{encryptedValueUuid, passwordCredentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
      jdbcTemplate.update(
          "update password_credential " +
              "set password_parameters_uuid = ? " +
              "where uuid = ?",
          new Object[]{encryptedValueUuid, passwordCredentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
    }

    final List<Object> usersWithEncryptedValues = jdbcTemplate.queryForList(
        "select uuid from user_credential where encrypted_generation_parameters is not null",
        Object.class);

    for (final Object userCredentialUuid : usersWithEncryptedValues) {
      final Object encryptedValueUuid = makeUuid(databaseName);
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
              "credential_version.uuid = ?;",
          new Object[]{encryptedValueUuid, userCredentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
      jdbcTemplate.update(
          "update user_credential " +
              "set password_parameters_uuid = ? " +
              "where uuid = ?",
          new Object[]{encryptedValueUuid, userCredentialUuid},
          new int[]{Types.VARBINARY, Types.VARBINARY}
      );
    }
  }
}
