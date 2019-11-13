package org.cloudfoundry.credhub.db.migration;

import java.time.Instant;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.DatabaseProfileResolver;
import org.cloudfoundry.credhub.domain.UserCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.repositories.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.services.DefaultCredentialVersionDataService;
import org.cloudfoundry.credhub.utils.UuidUtil;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test", }, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@SuppressFBWarnings(
  value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  justification = "Let's refactor this class into kotlin"
)
public class UserSaltMigrationTest {
  @Autowired
  private Flyway flyway;
  @Autowired
  private DefaultCredentialVersionDataService credentialVersionDataService;
  @Autowired
  private JdbcTemplate jdbcTemplate;
  @Autowired
  private EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;
  private String databaseName;
  private List<EncryptionKeyCanary> canaries;

  @SuppressFBWarnings(
    value = {
      "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
      "ODR_OPEN_DATABASE_RESOURCE",
    },
    justification = "Ignore that jdbcTemplate methods might return null or that the DB connection may be left open."
  )
  @Before
  public void beforeEach() throws Exception {
    canaries = encryptionKeyCanaryRepository.findAll();

    databaseName = jdbcTemplate.getDataSource()
      .getConnection()
      .getMetaData()
      .getDatabaseProductName()
      .toLowerCase();

    Flyway flywayV40 = Flyway
      .configure()
      .target(MigrationVersion.fromVersion("40"))
      .dataSource(flyway.getConfiguration().getDataSource())
      .locations(flyway.getConfiguration().getLocations())
      .load();

    flywayV40.clean();
    flywayV40.migrate();
  }

  @After
  public void afterEach() {
    flyway.clean();
    flyway.migrate();

    encryptionKeyCanaryRepository.saveAll(canaries);
    encryptionKeyCanaryRepository.flush();
  }

  @Test
  public void migratingAUserWithoutASalt_generatesASalt() {
    final String credentialName = "/test-user-credential";

    final Object encryptionKeyUuid = UuidUtil.makeUuid(databaseName);
    final Object credentialNameUuid = UuidUtil.makeUuid(databaseName);
    final Object userCredentialUuid = UuidUtil.makeUuid(databaseName);

    createCanary(encryptionKeyUuid);
    createCredential(encryptionKeyUuid, credentialName, credentialNameUuid, userCredentialUuid);

    flyway.migrate();

    final UserCredentialVersion migratedUser = (UserCredentialVersion) credentialVersionDataService.findMostRecent(credentialName);
    assertThat(migratedUser.getSalt().matches("^\\$6\\$[a-zA-Z0-9/.]{8}$"),
      equalTo(true));
  }

  @Test
  public void migratingMultipleUsersWithoutSalts_generatesDifferentSalts() {
    final String credentialName1 = "/test-user-credential1";
    final String credentialName2 = "/test-user-credential2";

    final Object encryptionKeyUuid = UuidUtil.makeUuid(databaseName);
    final Object credentialNameUuid1 = UuidUtil.makeUuid(databaseName);
    final Object userCredentialUuid1 = UuidUtil.makeUuid(databaseName);

    final Object credentialNameUuid2 = UuidUtil.makeUuid(databaseName);
    final Object userCredentialUuid2 = UuidUtil.makeUuid(databaseName);

    createCanary(encryptionKeyUuid);
    createCredential(encryptionKeyUuid, credentialName1, credentialNameUuid1, userCredentialUuid1);
    createCredential(encryptionKeyUuid, credentialName2, credentialNameUuid2, userCredentialUuid2);

    flyway.migrate();

    final UserCredentialVersion migratedUser1 = (UserCredentialVersion) credentialVersionDataService.findMostRecent(credentialName1);
    final UserCredentialVersion migratedUser2 = (UserCredentialVersion) credentialVersionDataService.findMostRecent(credentialName2);

    assertThat(migratedUser1.getSalt(), not(equalTo(migratedUser2.getSalt())));
  }

  @Transactional
  public void createCanary(final Object encryptionKeyUuid) {
    jdbcTemplate.update(
      "insert into encryption_key_canary (encrypted_value, nonce, uuid, salt) values (?, ?, ?, ?)",
      null,
      null,
      encryptionKeyUuid,
      null
    );
  }

  @Transactional
  public void createCredential(final Object encryptionKeyUuid, final String credentialName, final Object credentialNameUuid, final Object userCredentialUuid) {
    final Instant now = Instant.now();

    jdbcTemplate.update(
      "insert into credential_name (uuid, name) values (?, ?)",
      credentialNameUuid,
      credentialName
    );
    jdbcTemplate.update(
      "insert into credential (" +
        "type," +
        "encrypted_value," +
        "nonce," +
        "updated_at," +
        "uuid," +
        "encryption_key_uuid," +
        "version_created_at," +
        "credential_name_uuid" +
        ") values (?, ?, ?, ?, ?, ?, ?, ?)",
      "user",
      null,
      null,
      now.toEpochMilli(),
      userCredentialUuid,
      encryptionKeyUuid,
      now.toEpochMilli(),
      credentialNameUuid
    );
    jdbcTemplate.update(
      "insert into user_credential (uuid, username) values (?, ?)",
      userCredentialUuid,
      "test-username"
    );
  }
}
