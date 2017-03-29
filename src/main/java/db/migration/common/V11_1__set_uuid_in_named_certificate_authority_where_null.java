package db.migration.common;

import java.util.List;
import java.util.UUID;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

@SuppressWarnings("checkstyle:typename")
public class V11_1__set_uuid_in_named_certificate_authority_where_null implements
    SpringJdbcMigration {

  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
    List<Long> nullUuidRecords = jdbcTemplate.queryForList(
        "select id from named_certificate_authority where uuid is null",
        Long.class);

    for (Long record : nullUuidRecords) {
      jdbcTemplate.update(
          "update named_certificate_authority set uuid = ? where id = ?",
          UUID.randomUUID().toString(), record);
    }
  }
}
