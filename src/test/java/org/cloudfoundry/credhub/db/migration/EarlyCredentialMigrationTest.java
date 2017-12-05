package org.cloudfoundry.credhub.db.migration;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.List;
import java.util.UUID;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EarlyCredentialMigrationTest {

  @Autowired
  private Flyway flyway;
  @Autowired
  private Environment environment;
  @Autowired
  private NamedParameterJdbcTemplate namedParameterJdbcTemplate;
  @Autowired
  private JdbcTemplate jdbcTemplate;
  @Autowired
  private EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  private long id = 0;
  private List<EncryptionKeyCanary> canaries;

  @Before
  public void beforeEach() {
    canaries = encryptionKeyCanaryRepository.findAll();

    flyway.clean();
    flyway.setTarget(MigrationVersion.fromVersion("4"));
    flyway.migrate();
  }

  @After
  public void afterEach() {
    flyway.clean();
    flyway.setTarget(MigrationVersion.LATEST);
    flyway.migrate();

    encryptionKeyCanaryRepository.save(canaries);
    encryptionKeyCanaryRepository.flush();
  }

  @Test
  public void successfullyAppliesLatestMigration() {
    jdbcTemplate.update(
        "insert into named_canary (id, name, encrypted_value, nonce) values (?, ?, ?, ?)",
        10, "canary", "encrypted-value".getBytes(), "nonce".getBytes()
    );

    // we use raw sql because the entities assume the latest version
    storeValueSecret("test");
    storeValueSecret("/test");
    storeValueSecret("/deploy123/test");
  }

  private void storeValueSecret(String credentialName) {
    MapSqlParameterSource paramSource = new MapSqlParameterSource();
    String uuid = UUID.randomUUID().toString().replace("-", "");

    paramSource.addValue("id", id++);
    paramSource.addValue("type", "value");
    paramSource.addValue("encrypted_value", new byte[29]);
    paramSource.addValue("name", credentialName);
    paramSource.addValue("nonce", new byte[16]);
    paramSource.addValue("updated_at", 0);
    paramSource.addValue("uuid", uuid);

    boolean isPostgres = environment.acceptsProfiles("unit-test-postgres");
    String sql = "INSERT INTO named_secret("
        + (isPostgres ? "id, " : "")
        + "type, encrypted_value, name, nonce, updated_at, uuid) values ("
        + (isPostgres ? ":id, " : "")
        + ":type, :encrypted_value, :name, :nonce, :updated_at, :uuid)";
    namedParameterJdbcTemplate.update(sql, paramSource);

    long id = namedParameterJdbcTemplate
        .queryForObject("SELECT id FROM named_secret WHERE name = :name",
            new MapSqlParameterSource("name", credentialName), Long.class);

    namedParameterJdbcTemplate.update("INSERT INTO value_secret"
        + "(id) values (:id)", new MapSqlParameterSource("id", id));
  }
}
