package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionKeyService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretDataServiceTest {

  @Autowired
  SecretDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  PlatformTransactionManager transactionManager;
  TransactionStatus transaction;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @SpyBean
  EncryptionKeyService encryptionKeyService;

  private final Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;

  {
    wireAndUnwire(this, false);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from named_secret");
      jdbcTemplate.execute("delete from encryption_key_canary");
      fakeTimeSetter.accept(345345L);

      activeCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();

      when(encryptionKeyService.getActiveEncryptionKeyUuid()).thenReturn(activeCanaryUuid);
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_secret");
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    describe("#save", () -> {
      it("should save a secret", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedSecret savedSecret = subject.save(secret);

        assertNotNull(savedSecret);

        List<NamedPasswordSecret> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecret passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getName(), equalTo("my-secret"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("secret-password".getBytes()));

        // Because Java UUID doesn't let us convert from a byte[] to a type 4 UUID,
        // we need to use Hibernate to check the UUID :(
        passwordSecret = (NamedPasswordSecret) (secretRepository.findAll().get(0));
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should update a secret", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret-2");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret savedSecret = subject.save(secret);
        savedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        savedSecret.setEncryptedValue("irynas-ninja-skills".getBytes());

        subject.save(savedSecret);

        List<NamedPasswordSecret> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecret passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getName(), equalTo("my-secret-2"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));

        passwordSecret = (NamedPasswordSecret) (secretRepository.findAll().get(0));
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should generate a uuid when creating", () -> {
        NamedSshSecret secret = new NamedSshSecret("my-secret-2").setPublicKey("fake-public-key");
        NamedSshSecret savedSecret = subject.save(secret);

        UUID generatedUuid = savedSecret.getUuid();
        assertNotNull(generatedUuid);

        savedSecret.setPublicKey("updated-fake-public-key");
        savedSecret = subject.save(savedSecret);

        assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
      });

      describe("when the secret has no encrypted value", () -> {
        it("should set the default encryption key UUID", () -> {
          NamedSshSecret secret = new NamedSshSecret("my-secret").setPublicKey("fake-public-key");
          NamedSshSecret savedSecret = subject.save(secret);

          assertThat(savedSecret.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
        });
      });
    });

    describe("#delete", () -> {
      beforeEach(() -> {
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      });

      afterEach(() -> {
        transactionManager.rollback(transaction);
      });

      it("should delete all secrets matching a name", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);
        secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("my-secret");

        assertThat(subject.findAllByName("my-secret"), empty());
      });

      it("should be able to delete a secret ignoring case", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);
        secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("MY-SECRET");

        assertThat(subject.findContainingName("my-secret"), empty());
      });

      it("should cascade correctly", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("test-password");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(secret);
        NamedValueSecret namedValueSecret = new NamedValueSecret("test-value");
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret("test-certificate");
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
        NamedSshSecret namedSshSecret = new NamedSshSecret("test-ssh");
        namedSshSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSshSecret);
        NamedRsaSecret namedRsaSecret = new NamedRsaSecret("test-rsa");
        namedRsaSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedRsaSecret);

        assertThat(getSecretsFromDb().size(), equalTo(5));

        jdbcTemplate.execute("delete from named_secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });
    });

    describe("#findMostRecent", () -> {
      it("returns all secrets ignoring case", () -> {
        NamedPasswordSecret namedPasswordSecret1 = new NamedPasswordSecret("my-SECRET");
        namedPasswordSecret1.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret1.setEncryptedValue("my-password".getBytes());
        NamedPasswordSecret namedPasswordSecret2 = new NamedPasswordSecret("MY-SECRET");
        namedPasswordSecret2.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret2.setEncryptedValue("my-password".getBytes());
        subject.save(namedPasswordSecret1);
        fakeTimeSetter.accept(345346L); // 1 second later
        subject.save(namedPasswordSecret2);

        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject.findMostRecent("my-secret");
        assertThat(passwordSecret.getName(), equalTo("MY-SECRET"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("my-password".getBytes()));
      });

      it("finds most recent based on version_created_at date, not updated_at", () -> {
        NamedCertificateSecret firstCertificate = new NamedCertificateSecret("my-certificate");
        firstCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        firstCertificate.setCertificate("first-certificate");

        NamedCertificateSecret secondCertificate = new NamedCertificateSecret("my-certificate");
        secondCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        secondCertificate.setCertificate("second-certificate");

        firstCertificate = (NamedCertificateSecret) subject.save(firstCertificate);
        fakeTimeSetter.accept(345346L);
        secondCertificate = (NamedCertificateSecret) subject.save(secondCertificate);

        NamedCertificateSecret mostRecent = (NamedCertificateSecret) subject.findMostRecent("my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));

        firstCertificate.setCertificate("updated-first-certificate");
        fakeTimeSetter.accept(345347L);
        subject.save(firstCertificate);

        mostRecent = (NamedCertificateSecret) subject.findMostRecent("my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));
      });
    });

    describe("#findByUuid", () -> {
      it("should be able to find secret by uuid", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret");
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret savedSecret = subject.save(secret);

        assertNotNull(savedSecret.getUuid());
        NamedPasswordSecret oneByUuid = (NamedPasswordSecret) subject.findByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("my-secret"));
        assertThat(oneByUuid.getEncryptedValue(), equalTo("secret-password".getBytes()));
      });
    });

    describe("#findContainingName", () -> {
      String valueName = "value.Secret";
      String passwordName = "password/Secret";
      String certificateName = "certif/ic/atesecret";

      beforeEach(() -> {
        fakeTimeSetter.accept(2000000000123L);
        NamedValueSecret namedValueSecret = new NamedValueSecret(valueName);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedPasswordSecret namedPasswordSecret = new NamedPasswordSecret("mySe.cret");
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);

        fakeTimeSetter.accept(1000000000123L);
        namedPasswordSecret = new NamedPasswordSecret(passwordName);
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedPasswordSecret);
        NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret("myseecret");
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);

        fakeTimeSetter.accept(3000000000123L);
        namedCertificateSecret = new NamedCertificateSecret(certificateName);
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
      });

      it("returns secrets in reverse chronological order", () -> {
        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
      });

      it("should return secrets in order by version_created_at, not updated_at", () -> {
        NamedValueSecret valueSecret = (NamedValueSecret) subject.findMostRecent("value.Secret");
        valueSecret.setEncryptedValue("new-encrypted-value".getBytes());
        subject.save(valueSecret);
        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
      });

      it("should return a credential ignoring leading slash at the start of credential name", () -> {
        fakeTimeSetter.accept(4000000000123L);
        NamedPasswordSecret namedSecret = new NamedPasswordSecret("my/password/secret");
        namedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSecret);
        fakeTimeSetter.accept(5000000000123L);
        namedSecret = new NamedPasswordSecret("mypassword/secret");
        namedSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedSecret);
        List<NamedSecret> containingName = subject.findContainingName("/password");
        assertThat(containingName, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("my/password/secret")),
            hasProperty("name", equalTo(passwordName))
            ));
      });

      describe("when there are duplicate names", () -> {
        beforeEach(() -> {
          saveNamedPassword(2000000000123L, "foo/DUPLICATE");
          saveNamedPassword(1000000000123L, "foo/DUPLICATE");
          saveNamedPassword(3000000000123L, "bar/duplicate");
          saveNamedPassword(4000000000123L, "bar/duplicate");
        });

        it("should not return duplicate secret names", () -> {
          List<NamedSecret> secrets = subject.findContainingName("DUP");
          assertThat(secrets.size(), equalTo(2));
        });

        it("should return the most recent secret", () -> {
          List<NamedSecret> secrets = subject.findContainingName("DUP");

          NamedSecret secret = secrets.get(0);
          assertThat(secret.getName(), equalTo("bar/duplicate"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

          secret = secrets.get(1);
          assertThat(secret.getName(), equalTo("foo/DUPLICATE"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
        });
      });
    });

    describe("#findStartingWithName", () -> {
      beforeEach(() -> {
        saveNamedPassword(2000000000123L, "secret/1");
        saveNamedPassword(3000000000123L, "Secret/2");
        saveNamedPassword(1000000000123L, "SECRET/3");
        saveNamedPassword(1000000000123L, "not/So/Secret");
        saveNamedPassword(1000000000123L, "SECRETnotrailingslash");
      });

      it("should return a list of secrets in chronological order that start with a given string", () -> {
        List<NamedSecret> secrets = subject.findStartingWithName("Secret/");

        assertThat(secrets.size(), equalTo(3));
        assertThat(secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("Secret/2")),
            hasProperty("name", equalTo("secret/1")),
            hasProperty("name", equalTo("SECRET/3"))
        ));
        assertThat(secrets, not(contains(hasProperty("notSoSecret"))));
      });

      it("should return secrets in order by version_created_at, not updated_at", () -> {
        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject.findMostRecent("secret/1");
        passwordSecret.setEncryptedValue("new-encrypted-value".getBytes());
        subject.save(passwordSecret);
        List<NamedSecret> secrets = subject.findStartingWithName("Secret/");
        assertThat(secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("Secret/2")),
            hasProperty("name", equalTo("secret/1")),
            hasProperty("name", equalTo("SECRET/3"))
        ));
      });

      describe("when there are duplicate names", () -> {
        beforeEach(() -> {
          saveNamedPassword(2000000000123L, "DupSecret/1");
          saveNamedPassword(3000000000123L, "DupSecret/1");
          saveNamedPassword(1000000000123L, "DupSecret/1");
        });

        it("should not return duplicate secret names", () -> {
          List<NamedSecret> secrets = subject.findStartingWithName("dupsecret/");
          assertThat(secrets.size(), equalTo(1));
        });

        it("should return the most recent secret", () -> {
          List<NamedSecret> secrets = subject.findStartingWithName("dupsecret/");
          NamedSecret secret = secrets.get(0);
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
        });
      });

      describe("when the path does not have a trailing slash", () -> {
        it("should append an ending slash", () -> {
          List<NamedSecret> secrets = subject.findStartingWithName("Secret");

          assertThat(secrets.size(), equalTo(3));
          assertThat(secrets, not(contains(hasProperty("name", equalTo("SECRETnotrailingslash")))));
        });
      });
    });

    describe("#findAllPaths", () -> {
      beforeEach(() -> {
        String valueOther = "fubario";
        String valueName = "value/Secret";
        String passwordName = "password/Secret";
        String certificateName = "certif/ic/ateSecret";
        NamedValueSecret namedValueSecret = new NamedValueSecret(valueOther);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        namedValueSecret = new NamedValueSecret(valueName);
        namedValueSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedValueSecret);
        NamedPasswordSecret namedPasswordSecret = new NamedPasswordSecret(passwordName);
        namedPasswordSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedPasswordSecret);
        NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(certificateName);
        namedCertificateSecret.setEncryptionKeyUuid(activeCanaryUuid);
        subject.save(namedCertificateSecret);
      });

      it("can fetches possible paths for all secrets", () -> {
        assertThat(subject.findAllPaths(), equalTo(newArrayList("certif/", "certif/ic/", "password/", "value/")));
      });
    });

    describe("#findAllByName", () -> {
      it("finds all by name", () -> {
        NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "secret1");
        NamedPasswordSecret secret2 = saveNamedPassword(4000000000123L, "seCret1");
        saveNamedPassword(3000000000123L, "Secret2");

        List<NamedSecret> secrets = subject.findAllByName("Secret1");
        assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())), hasProperty("uuid", equalTo(secret2.getUuid()))));
      });
    });

    describe("#findAllNotEncryptedByActiveKey", () -> {
      it("should return all versions of all secrets encrypted with an old key", () -> {
        UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();

        NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "secret", oldCanaryUuid);
        NamedPasswordSecret secret2 = saveNamedPassword(3000000000123L, "ANOTHER", oldCanaryUuid);
        NamedPasswordSecret secret3 = saveNamedPassword(4000000000123L, "password", oldCanaryUuid);
        NamedPasswordSecret secret1Newer = saveNamedPassword(5000000000123L, "secret", oldCanaryUuid);

        NamedPasswordSecret secretEncryptedWithActiveKey = saveNamedPassword(3000000000123L, "ANOTHER", activeCanaryUuid);
        NamedPasswordSecret newerSecretEncryptedWithActiveKey = saveNamedPassword(4000000000123L, "ANOTHER", activeCanaryUuid);

        List<NamedSecret> secrets = subject.findAllNotEncryptedByActiveKey();
        List<UUID> secretUuids = secrets.stream().map(secret -> secret.getUuid()).collect(Collectors.toList());

        assertThat(secretUuids, not(contains(secretEncryptedWithActiveKey.getUuid())));
        assertThat(secretUuids, not(contains(newerSecretEncryptedWithActiveKey.getUuid())));

        assertThat(secretUuids, containsInAnyOrder(secret1.getUuid(), secret2.getUuid(), secret3.getUuid(), secret1Newer.getUuid()));
      });
    });
  }

  private NamedPasswordSecret saveNamedPassword(long timeMillis, String secretName, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    NamedPasswordSecret secretObject = new NamedPasswordSecret(secretName);
    secretObject.setEncryptionKeyUuid(canaryUuid);
    return subject.save(secretObject);
  }

  private NamedPasswordSecret saveNamedPassword(long timeMillis, String secretName) {
    return saveNamedPassword(timeMillis, secretName, activeCanaryUuid);
  }

  private List<NamedPasswordSecret> getSecretsFromDb() {
    return jdbcTemplate.query("select * from named_secret", (rowSet, rowNum) -> {
            NamedPasswordSecret passwordSecret = new NamedPasswordSecret(rowSet.getString("name"));

            passwordSecret.setUuid(UUID.nameUUIDFromBytes(rowSet.getBytes("uuid")));
            passwordSecret.setNonce(rowSet.getBytes("nonce"));
            passwordSecret.setEncryptedValue(rowSet.getBytes("encrypted_value"));

            return passwordSecret;
          });
  }
}
