package db.migration.common;

import java.sql.Types;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.utils.UuidUtil;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

@SuppressWarnings("unused")
public class V20_1__set_uuid_in_encryption_key_canary extends BaseJavaMigration {

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "The database will definitely exist"
  )
  @Override
  public void migrate(Context context) throws Exception {
    JdbcTemplate jdbcTemplate =
      new JdbcTemplate(new SingleConnectionDataSource(context.getConnection(), true));
    final String databaseName = jdbcTemplate
      .getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    final int[] types = {Types.VARBINARY, Types.BIGINT};

    final List<Long> canaryIds = jdbcTemplate.queryForList(
        "select id from encryption_key_canary",
        Long.class
    );

    for (final Long id : canaryIds) {
      jdbcTemplate.update(
          "update encryption_key_canary set uuid = ? where id = ?",
          getParams(databaseName, id),
          types
      );
    }
  }

  private Object[] getParams(final String databaseName, final Long id) {
    final UUID uuid = UUID.randomUUID();

    if ("postgresql".equals(databaseName)) {
      return new Object[]{uuid, id};
    } else {
      return new Object[]{UuidUtil.uuidToByteArray(uuid), id};
    }
  }
}
