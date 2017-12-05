package db.migration.common;

import org.cloudfoundry.credhub.util.UuidUtil;
import java.sql.Types;
import java.util.List;
import java.util.UUID;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

public class V20_1__set_uuid_in_encryption_key_canary implements SpringJdbcMigration {

  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
    String databaseName = jdbcTemplate.getDataSource().getConnection().getMetaData()
        .getDatabaseProductName().toLowerCase();
    int[] types = {Types.VARBINARY, Types.BIGINT};

    List<Long> canaryIds = jdbcTemplate.queryForList(
        "select id from encryption_key_canary",
        Long.class
    );

    for (Long id : canaryIds) {
      jdbcTemplate.update(
          "update encryption_key_canary set uuid = ? where id = ?",
          getParams(databaseName, id),
          types
      );
    }
  }

  private Object[] getParams(String databaseName, Long id) {
    UUID uuid = UUID.randomUUID();

    if (databaseName.equals("postgresql")) {
      return new Object[]{uuid, id};
    } else {
      return new Object[]{UuidUtil.uuidToByteArray(uuid), id};
    }
  }
}
