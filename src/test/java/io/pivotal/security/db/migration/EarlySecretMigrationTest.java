package io.pivotal.security.db.migration;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EarlySecretMigrationTest {

  private long id = 0;

  @Autowired
  Flyway flyway;

  @Autowired
  Environment environment;

  @Autowired
  NamedParameterJdbcTemplate namedParameterJdbcTemplate;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  JdbcTemplate jdbcTemplate;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      flyway.clean();
      flyway.setTarget(MigrationVersion.fromVersion("4"));
      flyway.migrate();
    });

    afterEach(() -> {
      flyway.setTarget(MigrationVersion.LATEST);
      flyway.migrate();
    });

    it("should apply the latest migration successfully", () -> {
      jdbcTemplate.update(
          "insert into named_canary (id, name, encrypted_value, nonce) values (?, ?, ?, ?)",
          10, "canary", "encrypted-value".getBytes(), "nonce".getBytes()
      );

      // we use raw sql because the entities assume the latest version
      storeValueSecret("test");
      storeValueSecret("/test");
      storeValueSecret("/deploy123/test");
    });
  }

  private void storeValueSecret(String secretName) {
    MapSqlParameterSource paramSource = new MapSqlParameterSource();
    String uuid = UUID.randomUUID().toString().replace("-", "");

    paramSource.addValue("id", id++);
    paramSource.addValue("type", "value");
    paramSource.addValue("encrypted_value", new byte[29]);
    paramSource.addValue("name", secretName);
    paramSource.addValue("nonce", new byte[16]);
    paramSource.addValue("updated_at", 0);
    paramSource.addValue("uuid", uuid);

    boolean isPostgres = environment.acceptsProfiles("unit-test-postgres");
    String sql = "INSERT INTO named_secret(" +
        (isPostgres ? "id, " : "") +
        "type, encrypted_value, name, nonce, updated_at, uuid) values (" +
        (isPostgres ? ":id, " : "") +
        ":type, :encrypted_value, :name, :nonce, :updated_at, :uuid)";
    namedParameterJdbcTemplate.update(sql, paramSource);

    long id = namedParameterJdbcTemplate.queryForObject("SELECT id FROM named_secret WHERE name = :name", new MapSqlParameterSource("name", secretName), Long.class);

    namedParameterJdbcTemplate.update("INSERT INTO value_secret" +
        "(id) values (:id)", new MapSqlParameterSource("id", id));
  }
}
