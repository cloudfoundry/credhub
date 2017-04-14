package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.SecretView;
import org.apache.commons.lang3.StringUtils;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Slice;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
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
import static org.junit.Assert.assertNull;
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
  SecretNameRepository nameRepository;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  SecretNameRepository secretNameRepository;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  private Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private UUID unknownCanaryUuid;
  private NamedPasswordSecretData namedPasswordSecret2;
  private NamedPasswordSecretData namedPasswordSecret1;
  private NamedValueSecretData namedValueSecretData;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(345345L);

      activeCanaryUuid = encryptionKeyCanaryMapper.getActiveUuid();
      unknownCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
          .getUuid();
    });

    describe("#save", () -> {
      it("should save a secret", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-secret");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
        NamedSecret savedSecret = subject.save(secret);

        assertNotNull(savedSecret);

        List<NamedPasswordSecretData> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecretData passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getSecretName().getName(), equalTo("/my-secret"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("secret-password".getBytes()));

        // Because Java UUID doesn't let us convert from a byte[] to a type 4 UUID,
        // we need to use Hibernate to check the UUID :(
        NamedPasswordSecretData foundPasswordSecret = (NamedPasswordSecretData) (secretRepository
            .findAll().get(0));
        assertThat(foundPasswordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should update a secret", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-secret-2");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);

        NamedPasswordSecret savedSecret = subject.save(secret);
        savedSecret.copyInto(secret);
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecretData.setEncryptedValue("irynas-ninja-skills".getBytes());

        subject.save(secret);

        List<NamedPasswordSecretData> passwordSecrets = getSecretsFromDb();

        assertThat(passwordSecrets.size(), equalTo(1));
        NamedPasswordSecretData passwordSecret = passwordSecrets.get(0);
        assertThat(passwordSecret.getSecretName().getName(), equalTo("/my-secret-2"));
        assertThat(passwordSecret.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));

        NamedPasswordSecretData foundPasswordSecret = (NamedPasswordSecretData) (secretRepository
            .findAll().get(0));
        assertThat(foundPasswordSecret.getUuid(), equalTo(secret.getUuid()));
      });

      it("should generate a uuid when creating", () -> {
        NamedSshSecret secret = new NamedSshSecret("/my-secret-2").setPublicKey("fake-public-key");
        NamedSshSecret savedSecret = subject.save(secret);

        UUID generatedUuid = savedSecret.getUuid();
        assertNotNull(generatedUuid);

        savedSecret.setPublicKey("updated-fake-public-key");
        savedSecret = subject.save(savedSecret);

        assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
      });

      it("should save with the leading slash", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/secret");
        NamedPasswordSecret secretWithLeadingSlash = new NamedPasswordSecret(namedPasswordSecretData);

        subject.save(secretWithLeadingSlash);

        NamedPasswordSecretData savedSecret = getSecretsFromDb().get(0);

        assertThat(savedSecret.getSecretName().getName(), equalTo("/my/secret"));
      });

      describe("when the secret has no encrypted value", () -> {
        it("should set the default encryption key UUID", () -> {
          NamedSshSecretData namedSshSecretData = new NamedSshSecretData("/my-secret");
          NamedSshSecret secret = new NamedSshSecret(namedSshSecretData).setPublicKey("fake-public-key");
          NamedSshSecret savedSecret = subject.save(secret);
          savedSecret.copyInto(secret);

          assertThat(namedSshSecretData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
        });
      });
    });

    describe("#delete", () -> {
      it("should return true if the secret exists", () -> {
        secretNameRepository.saveAndFlush(new SecretName("/my-secret"));

        assertThat(subject.delete("/my-secret"), equalTo(true));
      });

      it("should delete all secrets matching a name", () -> {
        SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("/my-secret"));

        NamedPasswordSecretData secret = new NamedPasswordSecretData();
        secret.setSecretName(secretName);
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);

        secret = new NamedPasswordSecretData();
        secret.setSecretName(secretName);
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);

        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("/my-secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
        assertNull(nameRepository.findOneByNameIgnoreCase("/my-secret"));
      });

      it("should be able to delete a secret ignoring case", () -> {
        SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("/my-secret"));

        NamedPasswordSecretData secret = new NamedPasswordSecretData();
        secret.setSecretName(secretName);
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("secret-password".getBytes());
        subject.save(secret);

        secret = new NamedPasswordSecretData();
        secret.setSecretName(secretName);
        secret.setEncryptionKeyUuid(activeCanaryUuid);
        secret.setEncryptedValue("another password".getBytes());
        subject.save(secret);

        assertThat(getSecretsFromDb().size(), equalTo(2));

        subject.delete("MY-SECRET");

        assertThat(subject.findContainingName("/my-secret"), empty());
      });

      it("should cascade correctly", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("test-password-for-delete");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
        subject.save(secret);

        NamedValueSecretData namedValueSecretData = new NamedValueSecretData("test-value");
        namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedValueSecret namedValueSecret = new NamedValueSecret(namedValueSecretData);
        subject.save(namedValueSecret);

        NamedCertificateSecretData namedCertificateSecretData =
            new NamedCertificateSecretData("test-certificate");
        namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedCertificateSecret namedCertificateSecret =
            new NamedCertificateSecret(namedCertificateSecretData);
        subject.save(namedCertificateSecret);

        NamedSshSecretData namedSshSecretData = new NamedSshSecretData("test-ssh");
        namedSshSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedSshSecret namedSshSecret = new NamedSshSecret(namedSshSecretData);
        subject.save(namedSshSecret);

        NamedRsaSecretData namedRsaSecretData = new NamedRsaSecretData("test-rsa");
        namedRsaSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedRsaSecret namedRsaSecret = new NamedRsaSecret(namedRsaSecretData);
        subject.save(namedRsaSecret);

        assertThat(getSecretsFromDb().size(), equalTo(5));

        jdbcTemplate.execute("delete from secret_name");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });

      it("should not need a leading slash to delete a secret", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/secret");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
        subject.save(secret);

        subject.delete("my/secret");

        assertThat(getSecretsFromDb().size(), equalTo(0));
      });

      describe("when the secret does not exist", () -> {
        it("returns false", () -> {
          assertThat(subject.delete("/does/not/exist"), equalTo(false));
        });
      });
    });

    describe("#findMostRecent when SecretName found without versions", () -> {
      beforeEach(() -> {
        secretNameRepository.saveAndFlush(new SecretName("/my-unused-SECRET"));
      });

      it("should return null", () -> {
        assertNull(subject.findMostRecent("/my-unused-SECRET"));
      });
    });

    describe("#findMostRecent", () -> {
      beforeEach(() -> {
        SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("/my-SECRET"));

        namedPasswordSecret1 = new NamedPasswordSecretData();
        namedPasswordSecret1.setSecretName(secretName);
        namedPasswordSecret1.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret1.setEncryptedValue("/my-old-password".getBytes());

        namedPasswordSecret2 = new NamedPasswordSecretData();
        namedPasswordSecret2.setSecretName(secretName);
        namedPasswordSecret2.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret2.setEncryptedValue("/my-new-password".getBytes());

        subject.save(namedPasswordSecret1);
        fakeTimeSetter.accept(345346L); // 1 second later
        subject.save(namedPasswordSecret2);
      });

      it("returns all secrets ignoring case", () -> {
        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
            .findMostRecent("/my-secret");
        assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
        assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
      });

      it("returns all secrets ignoring the leading slash", () -> {
        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
            .findMostRecent("my-secret");
        assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
        assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
      });

      it("finds most recent based on version_created_at date, not updated_at", () -> {
        SecretName secretName = secretNameRepository
            .saveAndFlush(new SecretName("/my-certificate"));

        NamedCertificateSecretData firstCertificate = new NamedCertificateSecretData();
        firstCertificate.setSecretName(secretName);
        firstCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        firstCertificate.setCertificate("first-certificate");

        NamedCertificateSecretData secondCertificate = new NamedCertificateSecretData();
        secondCertificate.setSecretName(secretName);
        secondCertificate.setEncryptionKeyUuid(activeCanaryUuid);
        secondCertificate.setCertificate("second-certificate");

        NamedCertificateSecret savedFirstCertificate;
        savedFirstCertificate = subject.save(firstCertificate);
        fakeTimeSetter.accept(445346L);
        subject.save(secondCertificate);

        NamedCertificateSecret mostRecent = (NamedCertificateSecret) subject
            .findMostRecent("/my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));

        firstCertificate.setCertificate("updated-first-certificate");
        fakeTimeSetter.accept(445347L);
        subject.save(savedFirstCertificate);

        mostRecent = (NamedCertificateSecret) subject.findMostRecent("/my-certificate");
        assertThat(mostRecent.getCertificate(), equalTo("second-certificate"));
      });
    });

    describe("#findByUuid", () -> {
      it("should be able to find secret by uuid", () -> {
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-secret");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
        NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
        NamedPasswordSecret savedSecret = subject.save(secret);

        assertNotNull(savedSecret.getUuid());
        NamedPasswordSecret oneByUuid = (NamedPasswordSecret) subject
            .findByUuid(savedSecret.getUuid().toString());
        assertThat(oneByUuid.getName(), equalTo("/my-secret"));
        assertThat(namedPasswordSecretData.getEncryptedValue(), equalTo("secret-password".getBytes()));
      });
    });

    describe("#findContainingName", () -> {
      String valueName = "/value.Secret";
      String passwordName = "/password/Secret";
      String certificateName = "/certif/ic/atesecret";

      beforeEach(() -> {
        fakeTimeSetter.accept(2000000000123L);
        namedValueSecretData = new NamedValueSecretData(valueName);
        namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedValueSecret namedValueSecret = new NamedValueSecret(namedValueSecretData);
        subject.save(namedValueSecret);

        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/mySe.cret");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedPasswordSecret namedPasswordSecret = new NamedPasswordSecret(namedPasswordSecretData);
        subject.save(namedValueSecret);

        fakeTimeSetter.accept(1000000000123L);
        namedPasswordSecretData = new NamedPasswordSecretData(passwordName);
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedPasswordSecret = new NamedPasswordSecret(namedPasswordSecretData);
        subject.save(namedPasswordSecret);

        NamedCertificateSecretData namedCertificateSecretData = new NamedCertificateSecretData(
            "/myseecret");
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(namedCertificateSecretData);
        subject.save(namedCertificateSecret);

        fakeTimeSetter.accept(3000000000123L);
        namedCertificateSecretData = new NamedCertificateSecretData(
            certificateName);
        namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedCertificateSecret = new NamedCertificateSecret(namedCertificateSecretData);
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
        namedValueSecretData.setEncryptedValue("new-encrypted-value".getBytes());
        subject.save(valueSecret);
        assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
      });

      it("should return a credential, not ignoring leading slash at the start of credential name",
          () -> {
            fakeTimeSetter.accept(4000000000123L);
            NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/password/secret");
            namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
            NamedPasswordSecret namedSecret = new NamedPasswordSecret(namedPasswordSecretData);
            subject.save(namedSecret);

            fakeTimeSetter.accept(5000000000123L);
            namedPasswordSecretData = new NamedPasswordSecretData("/mypassword/secret");
            namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
            namedSecret = new NamedPasswordSecret(namedPasswordSecretData);
            subject.save(namedSecret);

            List<SecretView> containingName = subject.findContainingName("/password");
            assertThat(containingName, IsIterableContainingInOrder.contains(
                hasProperty("name", equalTo("/my/password/secret")),
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
          List<SecretView> secrets = subject.findContainingName("DUP");
          assertThat(secrets.size(), equalTo(2));
        });

        it("should return the most recent secret", () -> {
          List<SecretView> secrets = subject.findContainingName("DUP");

          SecretView secret = secrets.get(0);
          assertThat(secret.getName(), equalTo("/bar/duplicate"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

          secret = secrets.get(1);
          assertThat(secret.getName(), equalTo("/foo/DUPLICATE"));
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
        });
      });
    });

    describe("#findStartingWithPath", () -> {
      beforeEach(() -> {
        saveNamedPassword(2000000000123L, "/secret/1");
        saveNamedPassword(3000000000123L, "/Secret/2");
        saveNamedPassword(1000000000123L, "/SECRET/3");
        saveNamedPassword(1000000000123L, "/not/So/Secret");
        saveNamedPassword(1000000000123L, "/SECRETnotrailingslash");
      });

      it("should return a list of secrets in chronological order that start with a given string",
          () -> {
            List<SecretView> secrets = subject.findStartingWithPath("Secret/");

            assertThat(secrets.size(), equalTo(3));
            assertThat(secrets, IsIterableContainingInOrder.contains(
                hasProperty("name", equalTo("/Secret/2")),
                hasProperty("name", equalTo("/secret/1")),
                hasProperty("name", equalTo("/SECRET/3"))
            ));
            assertThat(secrets, not(contains(hasProperty("notSoSecret"))));
          });

      it("should return secrets in order by version_created_at, not updated_at", () -> {
        NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
            .findMostRecent("secret/1");
        passwordSecret.setPasswordAndGenerationParameters("new-password", null);
        subject.save(passwordSecret);
        List<SecretView> secrets = subject.findStartingWithPath("Secret/");
        assertThat(secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Secret/2")),
            hasProperty("name", equalTo("/secret/1")),
            hasProperty("name", equalTo("/SECRET/3"))
        ));
      });

      describe("when there are duplicate names", () -> {
        beforeEach(() -> {
          saveNamedPassword(2000000000123L, "/DupSecret/1");
          saveNamedPassword(3000000000123L, "/DupSecret/1");
          saveNamedPassword(1000000000123L, "/DupSecret/1");
        });

        it("should not return duplicate secret names", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("/dupsecret/");
          assertThat(secrets.size(), equalTo(1));
        });

        it("should return the most recent secret", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("/dupsecret/");
          SecretView secret = secrets.get(0);
          assertThat(secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
        });
      });

      it("should ignore a leading slash", () -> {
        List<SecretView> secrets = subject.findStartingWithPath("Secret");

        assertThat(secrets.size(), equalTo(3));
        assertThat(secrets, not(contains(hasProperty("name", equalTo("/not/So/Secret")))));
      });

      describe("when the path does not have a trailing slash", () -> {
        it("should append an ending slash", () -> {
          List<SecretView> secrets = subject.findStartingWithPath("Secret");

          assertThat(secrets.size(), equalTo(3));
          assertThat(secrets,
              not(contains(hasProperty("name", equalTo("/SECRETnotrailingslash")))));
        });
      });
    });

    describe("#findAllPaths", () -> {
      beforeEach(() -> {
        String valueOther = "/fubario";
        String valueName = "/value/Secret";
        String passwordName = "/password/Secret";
        String certificateName = "/certif/ic/ateSecret";

        NamedValueSecretData namedValueSecretData = new NamedValueSecretData(valueOther);
        namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedValueSecret namedValueSecret = new NamedValueSecret(namedValueSecretData);
        subject.save(namedValueSecret);

        namedValueSecretData = new NamedValueSecretData(valueName);
        namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        namedValueSecret = new NamedValueSecret(namedValueSecretData);
        subject.save(namedValueSecret);

        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData(passwordName);
        namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedPasswordSecret namedPasswordSecret = new NamedPasswordSecret(namedPasswordSecretData);
        subject.save(namedPasswordSecret);

        NamedCertificateSecretData namedCertificateSecretData =
            new NamedCertificateSecretData(certificateName);
        namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
        NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(namedCertificateSecretData);
        subject.save(namedCertificateSecret);

      });

      it("can fetches possible paths for all secrets", () -> {
        assertThat(subject.findAllPaths(),
            equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
      });
    });

    describe("#findAllByName", () -> {
      describe("when there are matching secrets", () -> {
        it("finds all by name", () -> {
          NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "/secret1");
          NamedPasswordSecret secret2 = saveNamedPassword(4000000000123L, "/seCret1");
          saveNamedPassword(3000000000123L, "/Secret2");

          List<NamedSecret> secrets = subject.findAllByName("/Secret1");
          assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
              hasProperty("uuid", equalTo(secret2.getUuid()))));
        });

        it("finds all by name prepending the leading slash", () -> {
          NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "/secret1");
          NamedPasswordSecret secret2 = saveNamedPassword(4000000000123L, "/secret1");

          List<NamedSecret> secrets = subject.findAllByName("Secret1");
          assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
              hasProperty("uuid", equalTo(secret2.getUuid()))));
        });
      });

      describe("when there are no matching secrets", () -> {
        it("returns an empty list", () -> {
          assertThat(subject.findAllByName("does/NOT/exist"), empty());
        });
      });
    });

    describe("#findEncryptedWithAvailableInactiveKey", () -> {
      it("should return all versions of all secrets encrypted with a known and inactive key",
          () -> {
            UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
                .getUuid();

            when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
                .thenReturn(Arrays.asList(oldCanaryUuid));

            NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "secret",
                oldCanaryUuid);
            NamedPasswordSecret secret2 = saveNamedPassword(3000000000123L, "ANOTHER",
                oldCanaryUuid);
            NamedPasswordSecret secret3 = saveNamedPassword(4000000000123L, "password",
                oldCanaryUuid);
            NamedPasswordSecret secret1Newer = saveNamedPassword(5000000000123L, "secret",
                oldCanaryUuid);

            NamedPasswordSecret secretEncryptedWithActiveKey = saveNamedPassword(3000000000123L,
                "ANOTHER", activeCanaryUuid);
            NamedPasswordSecret newerSecretEncryptedWithActiveKey = saveNamedPassword(
                4000000000123L, "ANOTHER", activeCanaryUuid);

            NamedPasswordSecret secretEncryptedWithUnknownKey = saveNamedPassword(4000000000123L,
                "ANOTHER", unknownCanaryUuid);

            final Slice<NamedSecret> secrets = subject.findEncryptedWithAvailableInactiveKey();
            List<UUID> secretUuids = secrets.getContent().stream().map(secret -> secret.getUuid())
                .collect(Collectors.toList());

            assertThat(secretUuids, not(contains(secretEncryptedWithActiveKey.getUuid())));
            assertThat(secretUuids, not(contains(newerSecretEncryptedWithActiveKey.getUuid())));

            assertThat(secretUuids, not(contains(secretEncryptedWithUnknownKey.getUuid())));

            assertThat(secretUuids,
                containsInAnyOrder(secret1.getUuid(), secret2.getUuid(), secret3.getUuid(),
                    secret1Newer.getUuid()));
          });
    });
  }

  private NamedPasswordSecret saveNamedPassword(long timeMillis, String name, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    SecretName secretName = secretNameRepository
        .findOneByNameIgnoreCase(StringUtils.prependIfMissing(name, "/"));
    if (secretName == null) {
      secretName = secretNameRepository.saveAndFlush(new SecretName(name));
    }
    NamedPasswordSecretData secretObject = new NamedPasswordSecretData();
    secretObject.setSecretName(secretName);
    secretObject.setEncryptionKeyUuid(canaryUuid);
    return subject.save(secretObject);
  }

  private NamedPasswordSecret saveNamedPassword(long timeMillis, String secretName) {
    return saveNamedPassword(timeMillis, secretName, activeCanaryUuid);
  }

  private List<NamedPasswordSecretData> getSecretsFromDb() {
    List<SecretName> names = jdbcTemplate.query("select * from secret_name", (rowSet, rowNum) -> {
      SecretName secretName = new SecretName(rowSet.getString("name"));
      secretName.setUuid(UUID.nameUUIDFromBytes(rowSet.getBytes("uuid")));
      return secretName;
    });

    return jdbcTemplate.query("select * from named_secret", (rowSet, rowNum) -> {
      NamedPasswordSecretData passwordSecret = new NamedPasswordSecretData();

      UUID secretNameUuid = UUID.nameUUIDFromBytes(rowSet.getBytes("secret_name_uuid"));
      SecretName secretName = names.stream()
          .filter(x -> x.getUuid().equals(secretNameUuid))
          .findFirst()
          .orElseThrow(
              () -> new RuntimeException("Failed to appropriate SecretName for NamedSecret"));

      passwordSecret.setSecretName(secretName);
      passwordSecret.setUuid(UUID.nameUUIDFromBytes(rowSet.getBytes("uuid")));
      passwordSecret.setNonce(rowSet.getBytes("nonce"));
      passwordSecret.setEncryptedValue(rowSet.getBytes("encrypted_value"));

      return passwordSecret;
    });
  }
}
