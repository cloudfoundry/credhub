package io.pivotal.security.db.migration;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.util.UuidUtil;
import java.util.UUID;
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

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CertificateAuthorityCopyToSecretMigrationTest {

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
      flyway.setTarget(MigrationVersion.fromVersion("22"));
      flyway.migrate();
    });

    afterEach(() -> {
      flyway.setTarget(MigrationVersion.LATEST);
      flyway.migrate();
    });

    it("should rename authorities with conflicting names", () -> {
      // we use raw sql because the entities assume the latest version
      UUID existingCertUuid = storeCertificateSecret("authority");
      UUID otherExistingCertUuid = storeCertificateSecret("my-other-ca-cert");
      UUID conflictingNamedCertAuthorityUuid = storeNamedCertificateAuthority("authority");
      UUID nonConflictingNamedCertAuthorityUuid = storeNamedCertificateAuthority("one-more");

      flyway.setTarget(MigrationVersion.fromVersion("24"));
      flyway.migrate();

      assertThat(getSecretNameForUuid(existingCertUuid), equalTo("/authority"));
      assertThat(getSecretNameForUuid(otherExistingCertUuid), equalTo("/my-other-ca-cert"));
      assertThat(getSecretNameForUuid(conflictingNamedCertAuthorityUuid),
          equalTo("/authority-ca")); // gets -ca appended to it due to conflict
      assertThat(getSecretNameForUuid(nonConflictingNamedCertAuthorityUuid),
          equalTo("/one-more")); // no conflict, no -ca appended

      // It's self-signed and the ca_name is correct
      assertThat(getCaNameFromCertificateSecretForUuid(conflictingNamedCertAuthorityUuid),
          equalTo("/authority-ca"));
      assertThat(getCaNameFromCertificateSecretForUuid(nonConflictingNamedCertAuthorityUuid),
          equalTo("/one-more"));
    });

    it("updates ca_name values on certs when renaming and copying a ca", () -> {
      UUID ca = storeNamedCertificateAuthority("my-authority");
      UUID cert = storeCertificateSecret("my-cert", "my-authority"); // signed by ca
      UUID somethingWithTheSameName = storeCertificateSecret("my-authority", null);
      UUID importedCert = storeCertificateSecret("imported", null);
      UUID unrelatedCert = storeCertificateSecret("unrelated", "something-else");

      flyway.setTarget(MigrationVersion.fromVersion("24"));
      flyway.migrate();

      assertThat(getSecretNameForUuid(ca), equalTo("/my-authority-ca"));
      assertThat(getCaNameFromCertificateSecretForUuid(cert), equalTo("/my-authority-ca"));

      assertThat(getCaNameFromCertificateSecretForUuid(somethingWithTheSameName), equalTo(null));
      assertThat(getCaNameFromCertificateSecretForUuid(importedCert), equalTo(null));
      assertThat(getCaNameFromCertificateSecretForUuid(unrelatedCert), equalTo("/something-else"));
    });

    it("it does not change ca_name values when not adding -ca", () -> {
      UUID ca = storeNamedCertificateAuthority("my-authority");
      UUID cert = storeCertificateSecret("my-cert", "my-authority"); // signed by ca

      flyway.setTarget(MigrationVersion.fromVersion("24"));
      flyway.migrate();

      assertThat(getSecretNameForUuid(ca), equalTo("/my-authority"));
      assertThat(getSecretNameForUuid(cert), equalTo("/my-cert"));
      assertThat(getCaNameFromCertificateSecretForUuid(cert), equalTo("/my-authority"));
    });
  }

  private String getSecretNameForUuid(UUID uuid) {
    return namedParameterJdbcTemplate
        .queryForObject("SELECT name FROM named_secret WHERE uuid = :uuid AND type = 'cert'",
            new MapSqlParameterSource("uuid", uuidForDb(uuid)), String.class);
  }

  private String getCaNameFromCertificateSecretForUuid(UUID uuid) {
    return namedParameterJdbcTemplate
        .queryForObject("SELECT ca_name FROM certificate_secret WHERE uuid = :uuid",
            new MapSqlParameterSource("uuid", uuidForDb(uuid)), String.class);
  }

  // CREATE TABLE `named_certificate_authority` (
  //  `certificate` varchar(7000) DEFAULT NULL,
  //  `encrypted_value` blob,
  //  `name` varchar(255) NOT NULL,
  //  `nonce` tinyblob,
  //  `type` varchar(255) DEFAULT NULL,
  //  `updated_at` bigint(20) NOT NULL,
  //  `uuid` binary(16) NOT NULL,
  //  `encryption_key_uuid` binary(16) NOT NULL,
  //  `version_created_at` bigint(20) NOT NULL,
  //    PRIMARY KEY (`uuid`),
  //    KEY `named_certificate_authority_encryption_key_uuid_fkey` (`encryption_key_uuid`),
  //    CONSTRAINT `named_certificate_authority_encryption_key_uuid_fkey`
  //    FOREIGN KEY (`encryption_key_uuid`) REFERENCES `encryption_key_canary` (`uuid`)
  //) ENGINE=InnoDB DEFAULT CHARSET=utf8
  private UUID storeNamedCertificateAuthority(String authorityName) {
    MapSqlParameterSource paramSource = new MapSqlParameterSource();
    UUID uuid = UUID.randomUUID();
    UUID encryptionKeyUuid = createCanary();

    paramSource.addValue("certificate", "some certificate");
    paramSource.addValue("encrypted_value", "encrypted-value".getBytes());
    paramSource.addValue("name", authorityName);
    paramSource.addValue("nonce", new byte[16]);
    paramSource.addValue("updated_at", 0);
    paramSource.addValue("version_created_at", 0);
    paramSource.addValue("uuid", uuidForDb(uuid));
    paramSource.addValue("encryption_key_uuid", uuidForDb(encryptionKeyUuid));

    String sql = "INSERT INTO named_certificate_authority "
        + "(certificate, encrypted_value, name, nonce, updated_at,"
        + " version_created_at, uuid, encryption_key_uuid) "
        +
        "values "
        + "(:certificate, :encrypted_value, :name, :nonce, :updated_at,"
        + " :version_created_at, :uuid, :encryption_key_uuid)";
    namedParameterJdbcTemplate.update(sql, paramSource);

    return uuid;
  }

  // CREATE TABLE `certificate_secret` (
  //  `ca` varchar(7000) DEFAULT NULL,
  //  `certificate` varchar(7000) DEFAULT NULL,
  //  `ca_name` varchar(255) DEFAULT NULL,
  //  `uuid` binary(16) NOT NULL,
  //    PRIMARY KEY (`uuid`),
  //    CONSTRAINT `certificate_secret_uuid_fkey`
  //    FOREIGN KEY (`uuid`) REFERENCES `named_secret` (`uuid`) ON DELETE CASCADE
  //) ENGINE=InnoDB DEFAULT CHARSET=utf8
  //
  // CREATE TABLE `named_secret` (
  //  `type` varchar(31) NOT NULL,
  //  `encrypted_value` blob,
  //  `name` varchar(255) NOT NULL,
  //  `nonce` tinyblob,
  //  `updated_at` bigint(20) NOT NULL,
  //  `uuid` binary(16) NOT NULL,
  //  `encryption_key_uuid` binary(16) NOT NULL,
  //  `version_created_at` bigint(20) NOT NULL,
  //    PRIMARY KEY (`uuid`),
  //    UNIQUE KEY `named_secret_unique_uuid` (`uuid`),
  //    KEY `named_secret_encryption_key_uuid_fkey` (`encryption_key_uuid`),
  //    CONSTRAINT `named_secret_encryption_key_uuid_fkey`
  //    FOREIGN KEY (`encryption_key_uuid`) REFERENCES `encryption_key_canary` (`uuid`)
  //) ENGINE=InnoDB DEFAULT CHARSET=utf8
  private UUID storeSecret(String secretName, String type) {
    MapSqlParameterSource paramSource = new MapSqlParameterSource();
    UUID uuid = UUID.randomUUID();
    UUID encryptionKeyUuid = createCanary();

    paramSource.addValue("type", type);
    paramSource.addValue("encrypted_value", new byte[29]);
    paramSource.addValue("name", secretName);
    paramSource.addValue("nonce", new byte[16]);
    paramSource.addValue("updated_at", 0);
    paramSource.addValue("version_created_at", 0);
    paramSource.addValue("uuid", uuidForDb(uuid));
    paramSource.addValue("encryption_key_uuid", uuidForDb(encryptionKeyUuid));

    String sql = "INSERT INTO named_secret "
        + "(type, encrypted_value, name, nonce, updated_at,"
        + " version_created_at, uuid, encryption_key_uuid) "
        + "values "
        + "(:type, :encrypted_value, :name, :nonce, :updated_at,"
        + " :version_created_at, :uuid, :encryption_key_uuid)";
    namedParameterJdbcTemplate.update(sql, paramSource);

    return uuid;
  }

  private UUID storeCertificateSecret(String secretName) {
    return storeCertificateSecret(secretName, secretName);  // self-signed
  }

  private UUID storeCertificateSecret(String secretName, String caName) {
    UUID uuid = storeSecret(secretName, "cert");

    MapSqlParameterSource paramSource = new MapSqlParameterSource();
    paramSource.addValue("certificate", null);
    paramSource.addValue("ca_name", caName);
    paramSource.addValue("uuid", uuidForDb(uuid));

    namedParameterJdbcTemplate.update("INSERT INTO certificate_secret"
        + "(certificate, ca_name, uuid) values (:certificate, :ca_name, :uuid)", paramSource);

    return uuid;
  }

  private UUID createCanary() {
    UUID encryptionKeyUuid = UUID.randomUUID();

    jdbcTemplate.update(
        "insert into encryption_key_canary (encrypted_value, nonce, uuid) values (?, ?, ?)",
        "encrypted-value".getBytes(), "nonce".getBytes(), uuidForDb(encryptionKeyUuid)
    );

    return encryptionKeyUuid;
  }

  private Object uuidForDb(UUID uuid) {
    boolean isMysql = environment.acceptsProfiles("unit-test-mysql");
    boolean isPostgres = environment.acceptsProfiles("unit-test-postgres");
    if (isMysql) {
      return UuidUtil.uuidToByteArray(uuid);
    } else if (isPostgres) {
      return uuid;
    } else {
      return uuid.toString().replace("-", "");
    }
  }

}
