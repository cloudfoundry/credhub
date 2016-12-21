package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

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

  private final Consumer<Long> fakeTimeSetter;

  {
    wireAndUnwire(this, false);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      subject.secretRepository.deleteAll();
      fakeTimeSetter.accept(345345L);
    });

    afterEach(() -> {
      subject.secretRepository.deleteAll();
    });

    it("should have a secret repository", () -> {
      assertNotNull(subject.secretRepository);
    });

    describe("#save", () -> {
      it("should save a secret", () -> {
        NamedSecret secret = new NamedPasswordSecret("my-secret", "secret-password");
        NamedSecret savedSecret = subject.save(secret);

        assertNotNull(savedSecret);

        List<NamedPasswordSecret> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecret passwordSecret = passwordSecrets.get(0);
        assertNotNull(passwordSecret.getUuid());
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
        assertThat(passwordSecret.getName(), equalTo("my-secret"));
        assertThat(passwordSecret.getValue(), equalTo("secret-password"));
      });

      it("should update a secret", () -> {
        NamedSecret secret = new NamedPasswordSecret("my-secret-2", "secret-password");
        NamedPasswordSecret savedSecret = (NamedPasswordSecret) subject.save(secret);
        savedSecret.setValue("irynas-ninja-skills");

        subject.save(savedSecret);

        List<NamedPasswordSecret> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecret passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getName(), equalTo("my-secret-2"));
        assertThat(passwordSecret.getValue(), equalTo("irynas-ninja-skills"));
        assertNotNull(passwordSecret.getUuid());
        assertThat(passwordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should generate a uuid when creating", () -> {
        NamedSecret secret = new NamedSshSecret("my-secret-2").setPublicKey("fake-public-key");
        NamedSshSecret savedSecret = (NamedSshSecret) subject.save(secret);

        UUID generatedUuid = savedSecret.getUuid();
        assertNotNull(generatedUuid);

        savedSecret.setPublicKey("updated-fake-public-key");
        savedSecret = (NamedSshSecret) subject.save(savedSecret);

        assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
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
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret", "secret-password");
        subject.save(secret);
        secret = new NamedPasswordSecret("my-secret", "another password");
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("my-secret");

        assertThat(subject.findAllByName("my-secret"), empty());
      });

      it("should be able to delete a secret ignoring case", () -> {
        NamedPasswordSecret secret = new NamedPasswordSecret("my-secret", "secret-password");
        subject.save(secret);
        secret = new NamedPasswordSecret("my-secret", "another password");
        subject.save(secret);
        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("MY-SECRET");

        assertThat(subject.findContainingName("my-secret"), empty());
      });

      it("should cascade correctly", () -> {
        subject.save(new NamedPasswordSecret("test-password"));
        subject.save(new NamedValueSecret("test-value"));
        subject.save(new NamedCertificateSecret("test-certificate"));
        subject.save(new NamedSshSecret("test-ssh"));
        subject.save(new NamedRsaSecret("test-rsa"));

        assertThat(getSecretsFromDb().size(), equalTo(5));

        jdbcTemplate.execute("delete from named_secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });
    });

    describe("#findMostRecent", () -> {
      it("returns all secrets ignoring case", () -> {
        NamedPasswordSecret namedPasswordSecret1 = new NamedPasswordSecret("my-SECRET", "my-password");
        NamedPasswordSecret namedPasswordSecret2 = new NamedPasswordSecret("MY-SECRET-2", "my-password");
        subject.save(namedPasswordSecret1);
        subject.save(namedPasswordSecret2);

        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject.findMostRecent("my-secret");
        assertThat(passwordSecret.getName(), equalTo("my-SECRET"));
        assertThat(passwordSecret.getValue(), equalTo("my-password"));
      });
    });

    describe("#findByUuid", () -> {
      it("should be able to find secret by uuid", () -> {
        NamedSecret secret = new NamedPasswordSecret("my-secret", "secret-password");
        NamedPasswordSecret savedSecret = (NamedPasswordSecret) subject.save(secret);

        assertNotNull(savedSecret.getUuid());
        NamedPasswordSecret oneByUuid = (NamedPasswordSecret) subject.findByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("my-secret"));
        assertThat(oneByUuid.getValue(), equalTo("secret-password"));
      });
    });

    describe("#findContainingName", () -> {
      it("returns secrets in reverse chronological order", () -> {
        fakeTimeSetter.accept(2000000000123L);
        String valueName = "value.Secret";
        subject.save(new NamedValueSecret(valueName));
        subject.save(new NamedPasswordSecret("mySe.cret"));

        fakeTimeSetter.accept(1000000000123L);
        String passwordName = "password/Secret";
        subject.save(new NamedPasswordSecret(passwordName));
        subject.save(new NamedCertificateSecret("myseecret"));

        fakeTimeSetter.accept(3000000000123L);
        String certificateName = "certif/ic/atesecret";
        subject.save(new NamedCertificateSecret(certificateName));

        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
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
          assertThat(secret.getUpdatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

          secret = secrets.get(1);
          assertThat(secret.getName(), equalTo("foo/DUPLICATE"));
          assertThat(secret.getUpdatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
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
          assertThat(secret.getUpdatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
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
        subject.save(new NamedValueSecret(valueOther));
        subject.save(new NamedValueSecret(valueName));
        subject.save(new NamedPasswordSecret(passwordName));
        subject.save(new NamedCertificateSecret(certificateName));
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
  }

  private NamedPasswordSecret saveNamedPassword(long timeMillis, String secretName) {
    fakeTimeSetter.accept(timeMillis);
    NamedPasswordSecret secretObject = new NamedPasswordSecret(secretName);
    return (NamedPasswordSecret) subject.save(secretObject);
  }

  private List<NamedPasswordSecret> getSecretsFromDb() {
    return jdbcTemplate.query("select * from named_secret", (rowSet, rowNum) -> {
      ByteBuffer byteBuffer = ByteBuffer.wrap(rowSet.getBytes("uuid"));
      NamedPasswordSecret passwordSecret = new NamedPasswordSecret(rowSet.getString("name"));

      passwordSecret.setUuid(new UUID(byteBuffer.getLong(), byteBuffer.getLong()));
      passwordSecret.setNonce(rowSet.getBytes("nonce"));
      passwordSecret.setEncryptedValue(rowSet.getBytes("encrypted_value"));

      return passwordSecret;
    });
  }
}
