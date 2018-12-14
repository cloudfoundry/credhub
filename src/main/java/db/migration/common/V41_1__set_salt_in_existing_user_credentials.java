package db.migration.common;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.credential.CryptSaltFactory;
import org.cloudfoundry.credhub.util.StringUtil;
import org.cloudfoundry.credhub.util.UuidUtil;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;

@SuppressWarnings("unused")
public class V41_1__set_salt_in_existing_user_credentials implements SpringJdbcMigration {

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "The database will definitely exist"
  )
  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {

    String databaseName = jdbcTemplate
      .getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    CryptSaltFactory saltFactory = new CryptSaltFactory();

    List<UUID> uuids = jdbcTemplate.query("select uuid from user_credential", (rowSet, rowNum) -> {
      byte[] uuidBytes = rowSet.getBytes("uuid");
      if (databaseName.equals("postgresql")) {
        return UUID.fromString(new String(uuidBytes, StringUtil.UTF_8));
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
