package db.migration.common;

import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.util.UuidUtil;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

@SuppressWarnings("unused")
public class V41_1__set_salt_in_existing_user_credentials implements SpringJdbcMigration {
  @Override
  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
    CryptSaltFactory saltFactory = new CryptSaltFactory();

    String databaseName = jdbcTemplate.getDataSource().getConnection().getMetaData()
        .getDatabaseProductName().toLowerCase();

    List<UUID> uuids = jdbcTemplate.query("select uuid from user_credential", (rowSet, rowNum) -> {
      byte[] uuidBytes = rowSet.getBytes("uuid");
      if (databaseName.equals("postgresql")) {
        return UUID.fromString(new String(uuidBytes));
      } else {
        ByteBuffer byteBuffer = ByteBuffer.wrap(uuidBytes);
        return new UUID(byteBuffer.getLong(), byteBuffer.getLong());
      }
    });

    for (UUID uuid: uuids) {
      String salt = saltFactory.generateSalt();

      jdbcTemplate.update(
          "update user_credential set salt = ? where uuid = ?",
          new Object[]{salt, getUuidParam(databaseName, uuid)}
      );
    }
  }

  private Object getUuidParam(String databaseName, UUID uuid) {
    if (databaseName.equals("postgresql")) {
      return uuid;
    } else {
      return UuidUtil.uuidToByteArray(uuid);
    }
  }
}
