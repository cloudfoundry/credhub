package io.pivotal.security.db.migration;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;

import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test"})
public class MigrationsTest {

  private long id = 0;

  @Autowired
  Flyway flyway;

  @Autowired
  Environment environment;

  @Autowired
  NamedParameterJdbcTemplate jdbcTemplate;

  {
    wireAndUnwire(this);

    it("should apply the migration successfully", () -> {
      flyway.clean();
      flyway.setTarget(MigrationVersion.fromVersion("1"));
      flyway.migrate();

      // we use raw sql because the entities assume the latest version
      storeValueSecret("test");
      storeValueSecret("/test");
      storeValueSecret("/deploy123/test");

      flyway.setTarget(MigrationVersion.LATEST);
      flyway.migrate();
    });
  }

  private void storeValueSecret(String secretName) {
    MapSqlParameterSource paramSource = new MapSqlParameterSource();

    paramSource.addValue("id", id++);
    paramSource.addValue("type", "value");
    paramSource.addValue("encrypted_value", new byte[29]);
    paramSource.addValue("name", secretName);
    paramSource.addValue("nonce", new byte[16]);
    paramSource.addValue("updated_at", 0);
    paramSource.addValue("uuid", "00000000-0000-0000-0000-000000000001");

    boolean isPostgres = environment.acceptsProfiles("unit-test-postgres");
    String sql = "INSERT INTO named_secret(" +
        (isPostgres ? "id, " : "") +
        "type, encrypted_value, name, nonce, updated_at, uuid) values (" +
        (isPostgres ? ":id, " : "") +
        ":type, :encrypted_value, :name, :nonce, :updated_at, :uuid)";
    jdbcTemplate.update(sql, paramSource);

    long id = jdbcTemplate.queryForObject("SELECT id FROM named_secret WHERE name = :name", new MapSqlParameterSource("name", secretName), Long.class);

    jdbcTemplate.update("INSERT INTO value_secret" +
        "(id) values (:id)", new MapSqlParameterSource("id", id));
  }
}
