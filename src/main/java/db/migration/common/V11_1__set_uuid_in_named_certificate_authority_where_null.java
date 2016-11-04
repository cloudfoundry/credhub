package db.migration.common;

import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.UUID;

public class V11_1__set_uuid_in_named_certificate_authority_where_null implements SpringJdbcMigration {
  public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
    jdbcTemplate.update(
        "update named_certificate_authority set uuid = ? where uuid is null",
        UUID.randomUUID().toString());
  }
}
