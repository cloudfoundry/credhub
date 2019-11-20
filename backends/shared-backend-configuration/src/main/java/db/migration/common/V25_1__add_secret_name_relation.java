package db.migration.common;

import java.sql.Types;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.utils.UuidUtil;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;

@SuppressWarnings("unused")
public class V25_1__add_secret_name_relation implements SpringJdbcMigration {

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "The database will definitely exist"
  )
  @Override
  public void migrate(final JdbcTemplate jdbcTemplate) throws Exception {
    final String databaseName = jdbcTemplate
      .getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    final List<String> names = jdbcTemplate
        .queryForList("select distinct(name) from named_secret", String.class);

    for (final String name : names) {
      jdbcTemplate.update(
          "insert into secret_name (uuid, name) values (?, ?)",
          new Object[]{UuidUtil.makeUuid(databaseName), name},
          new int[]{Types.VARBINARY, Types.VARCHAR}
      );
    }
  }
}
