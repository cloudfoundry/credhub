package db.migration.common;

import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

@SuppressWarnings("unused")
public class V11_1__set_uuid_in_named_certificate_authority_where_null extends BaseJavaMigration {

  @Override
  public void migrate(final Context context) throws Exception {
    final JdbcTemplate jdbcTemplate =
      new JdbcTemplate(new SingleConnectionDataSource(context.getConnection(), true));
    final List<Long> nullUuidRecords = jdbcTemplate.queryForList(
      "select id from named_certificate_authority where uuid is null",
      Long.class);

    for (final Long record : nullUuidRecords) {
      jdbcTemplate.update(
        "update named_certificate_authority set uuid = ? where id = ?",
        UUID.randomUUID().toString(), record);
    }

  }
}
