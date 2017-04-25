package io.pivotal.security.helper;

import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

public class DatabaseHelper {
  public static void cleanUpDatabase(ApplicationContext applicationContext) {
    JdbcTemplate jdbcTemplate = applicationContext.getBean(JdbcTemplate.class);
    jdbcTemplate.execute("delete from credential_name");
    jdbcTemplate.execute("truncate table auth_failure_audit_record");
    jdbcTemplate.execute("delete from event_audit_record");
    jdbcTemplate.execute("delete from request_audit_record");
    jdbcTemplate.execute("delete from encryption_key_canary");
    jdbcTemplate.execute("truncate table access_entry");

    EncryptionKeyCanaryMapper encryptionKeyCanaryMapper = applicationContext
        .getBean(EncryptionKeyCanaryMapper.class);
    encryptionKeyCanaryMapper.mapUuidsToKeys();
  }
}
