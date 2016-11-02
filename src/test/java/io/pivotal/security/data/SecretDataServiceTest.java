package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
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

import java.util.List;
import java.util.function.Consumer;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SecretDataServiceTest {

  @Autowired
  SecretDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  PlatformTransactionManager transactionManager;
  TransactionStatus transaction;

  private final Consumer<Long> fakeTimeSetter;

  {
    wireAndUnwire(this);
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
      });
    });

    describe("#deleteByNameIgnoreCase", () -> {
      beforeEach(() -> {
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      });
      afterEach(() -> {
        transactionManager.rollback(transaction);
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
        NamedPasswordSecret oneByUuid = (NamedPasswordSecret) subject.findByUuid(savedSecret.getUuid());
        assertThat(oneByUuid.getName(), equalTo("my-secret"));
        assertThat(oneByUuid.getValue(), equalTo("secret-password"));
      });
    });

    describe("#findContainingName", () -> {
      it("returns secrets in reverse chronological order", () -> {
        fakeTimeSetter.accept(20000000L);
        String valueName = "value.Secret";
        subject.save(new NamedValueSecret(valueName));
        subject.save(new NamedPasswordSecret("mySe.cret"));

        fakeTimeSetter.accept(10000000L);
        String passwordName = "password/Secret";
        subject.save(new NamedPasswordSecret(passwordName));
        subject.save(new NamedCertificateSecret("myseecret"));

        fakeTimeSetter.accept(30000000L);
        String certificateName = "certif/ic/atesecret";
        subject.save(new NamedCertificateSecret(certificateName));

        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));

      });
    });

    describe("#findStartingWithName", () -> {
      beforeEach(() -> {
        saveNamedPassword(20000000L, "secret/1");
        saveNamedPassword(30000000L, "Secret/2");
        saveNamedPassword(10000000L, "SECRET/3");
        saveNamedPassword(10000000L, "not/So/Secret");
        saveNamedPassword(10000000L, "SECRETnotrailingslash");
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
        NamedPasswordSecret secret1 = saveNamedPassword(20000000L, "secret1");
        NamedPasswordSecret secret2 = saveNamedPassword(40000000L, "secret1");
        saveNamedPassword(30000000L, "Secret2");

        List<NamedSecret> secrets = subject.findAllByName("secret1");
        assertThat(secrets, containsInAnyOrder(hasProperty("id", equalTo(secret1.getId())), hasProperty("id", equalTo(secret2.getId()))));
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
            NamedPasswordSecret passwordSecret = new NamedPasswordSecret(rowSet.getString("name"));

            passwordSecret.setId(rowSet.getLong("id"));
            passwordSecret.setNonce(rowSet.getBytes("nonce"));
            passwordSecret.setEncryptedValue(rowSet.getBytes("encrypted_value"));

            return passwordSecret;
          });
  }
}
