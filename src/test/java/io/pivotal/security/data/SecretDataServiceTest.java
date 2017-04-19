package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedSecretData;
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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Slice;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class SecretDataServiceTest {

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

  @Autowired
  SecretDataService subject;

  private Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private UUID unknownCanaryUuid;
  private NamedPasswordSecretData namedPasswordSecret2;
  private NamedPasswordSecretData namedPasswordSecret1;
  private NamedValueSecretData namedValueSecretData;

  @Before
  public void beforeEach() {
    fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);
    fakeTimeSetter.accept(345345L);

    activeCanaryUuid = encryptionKeyCanaryMapper.getActiveUuid();
    unknownCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();
  }

  @Test
  public void save_givenANewSecret_savesTheSecret() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-secret");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
    NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
    NamedSecret savedSecret = subject.save(secret);

    assertNotNull(savedSecret);

    NamedPasswordSecret savedPasswordSecret = (NamedPasswordSecret) subject.findMostRecent("/my-secret");
    NamedSecretData secretData = secretRepository.findOneByUuid(savedSecret.getUuid());

    assertThat(savedPasswordSecret.getName(), equalTo(secret.getName()));
    assertThat(savedPasswordSecret.getUuid(), equalTo(secret.getUuid()));

    assertThat(secretData.getSecretName().getName(), equalTo("/my-secret"));
    assertThat(secretData.getEncryptedValue(), equalTo("secret-password".getBytes()));
  }

  @Test
  public void save_givenAnExistingSecret_updatesTheSecret() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-secret-2");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
    NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);

    subject.save(secret);

    namedPasswordSecretData.setEncryptedValue("irynas-ninja-skills".getBytes());

    subject.save(secret);

    NamedPasswordSecret savedPasswordSecret = (NamedPasswordSecret) subject.findMostRecent("/my-secret-2");
    NamedSecretData secretData = secretRepository.findOneByUuid(savedPasswordSecret.getUuid());

    assertThat(secretData.getSecretName().getName(), equalTo("/my-secret-2"));
    assertThat(secretData.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));
    assertThat(secretData.getUuid(), equalTo(secret.getUuid()));
  }

  @Test
  public void save_givenANewSecret_generatesTheUuid() {
    NamedSshSecret secret = new NamedSshSecret("/my-secret-2").setPublicKey("fake-public-key");
    NamedSshSecret savedSecret = subject.save(secret);

    UUID generatedUuid = savedSecret.getUuid();
    assertNotNull(generatedUuid);

    savedSecret.setPublicKey("updated-fake-public-key");
    savedSecret = subject.save(savedSecret);

    assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenASecretWithALeadingSlash_savesWithTheLeadingSlash() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/secret");
    NamedPasswordSecret secretWithLeadingSlash = new NamedPasswordSecret(namedPasswordSecretData);

    subject.save(secretWithLeadingSlash);

    NamedSecret savedSecret = subject.findMostRecent("/my/secret");
    assertThat(savedSecret.getSecretName().getName(), equalTo("/my/secret"));
  }

  @Test
  public void save_whenTheSecretSavedWithoutAnEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    NamedSshSecretData namedSshSecretData = new NamedSshSecretData("/my-secret");
    NamedSshSecret secret = new NamedSshSecret(namedSshSecretData).setPublicKey("fake-public-key");
    subject.save(secret);

    assertThat(namedSshSecretData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void delete_onAnExistingSecret_returnsTrue() {
    secretNameRepository.saveAndFlush(new SecretName("/my-secret"));

    assertThat(subject.delete("/my-secret"), equalTo(true));
  }

  @Test
  public void delete_onASecretName_deletesAllSecretsWithTheName() {
    SecretName secretName = secretNameRepository.saveAndFlush(new SecretName("/my-secret"));

    NamedPasswordSecretData secret = new NamedPasswordSecretData();
    secret.setSecretName(secretName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("secret-password".getBytes());
    subject.save(secret);

    secret = new NamedPasswordSecretData("/my-secret");
    secret.setSecretName(secretName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("another password".getBytes());
    subject.save(secret);

    assertThat(subject.findAllByName("/my-secret"), hasSize(2));

    subject.delete("/my-secret");

    assertThat(subject.findAllByName("/my-secret"), hasSize(0));
    assertNull(nameRepository.findOneByNameIgnoreCase("/my-secret"));
  }

  @Test
  public void delete_givenASecretNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
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

    assertThat(subject.findAllByName("/my-secret"), hasSize(2));

    subject.delete("MY-SECRET");

    assertThat(subject.findAllByName("/my-secret"), empty());
  }

  @Test
  public void delete_givenASecretNameWithoutALeadingSlash_deletesTheSecretAnyway() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/secret");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("secret-password".getBytes());
    NamedPasswordSecret secret = new NamedPasswordSecret(namedPasswordSecretData);
    subject.save(secret);

    subject.delete("my/secret");

    assertThat(subject.findAllByName("/my/secret"), hasSize(0));
  }

  @Test
  public void delete_givenANonExistentSecretName_returnsFalse() {
    assertThat(subject.delete("/does/not/exist"), equalTo(false));
  }

  @Test
  public void findMostRecent_givenASecretNameWithoutVersions_returnsNull() {
    secretNameRepository.saveAndFlush(new SecretName("/my-unused-SECRET"));

    assertNull(subject.findMostRecent("/my-unused-SECRET"));
  }

  @Test
  public void findMostRecent_givenASecretName_returnsMostRecentSecretWithoutCaseSensitivity() {
    setupTestFixtureForFindMostRecent();

    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
        .findMostRecent("/my-secret");
    assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
    assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findMostRecent_givenASecretName_returnsTheMostRecentSecretIgnoringTheLeadingSlash() {
    setupTestFixtureForFindMostRecent();

    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
        .findMostRecent("my-secret");
    assertThat(passwordSecret.getName(), equalTo("/my-SECRET"));
    assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findByUuid_givenAUuid_findsTheSecret() {
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
  }

  @Test
  public void findContainingName_givenASecretName_returnsSecretsInReverseChronologicalOrder() {
    String valueName = "/value.Secret";
    String passwordName = "/password/Secret";
    String certificateName = "/certif/ic/atesecret";

    setupTestFixturesForFindContainingName(valueName, passwordName, certificateName);

    assertThat(subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo(certificateName)),
        hasProperty("name", equalTo(valueName)),
        hasProperty("name", equalTo(passwordName))));

    NamedValueSecret valueSecret = (NamedValueSecret) subject.findMostRecent("value.Secret");
    namedValueSecretData.setEncryptedValue("new-encrypted-value".getBytes());
    subject.save(valueSecret);

    assertThat("The secrets are ordered by versionCreatedAt",
        subject.findContainingName("SECRET"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
  }

  @Test
  public void findContainingName_whenThereAreMultipleVerionsOfASecret() {

    saveNamedPassword(2000000000123L, "foo/DUPLICATE");
    saveNamedPassword(1000000000123L, "foo/DUPLICATE");
    saveNamedPassword(3000000000123L, "bar/duplicate");
    saveNamedPassword(4000000000123L, "bar/duplicate");

    List<SecretView> secrets = subject.findContainingName("DUP");
    assertThat("should only return unique secret names", secrets.size(), equalTo(2));

    SecretView secret = secrets.get(0);
    assertThat(secret.getName(), equalTo("/bar/duplicate"));
    assertThat("should return the most recently created version",
        secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

    secret = secrets.get(1);
    assertThat(secret.getName(), equalTo("/foo/DUPLICATE"));
    assertThat("should return the most recently created version",
        secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
  }

  @Test
  public void findStartingWithPath_whenProvidedAPath_returnsTheListOfOrderedSecrets() {
    setupTestFixtureForFindStartingWithPath();

    List<SecretView> secrets = subject.findStartingWithPath("Secret/");

    assertThat(secrets.size(), equalTo(3));
    assertThat(secrets, IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo("/Secret/2")),
        hasProperty("name", equalTo("/secret/1")),
        hasProperty("name", equalTo("/SECRET/3"))
    ));
    assertThat(
        "should return a list of secrets in chronological order that start with a given string",
        secrets, not(contains(hasProperty("notSoSecret"))));

    NamedPasswordSecret passwordSecret = (NamedPasswordSecret) subject
        .findMostRecent("secret/1");
    passwordSecret.setPasswordAndGenerationParameters("new-password", null);
    subject.save(passwordSecret);
    secrets = subject.findStartingWithPath("Secret/");
    assertThat("should return secrets in order by version_created_at, not updated_at",
        secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Secret/2")),
            hasProperty("name", equalTo("/secret/1")),
            hasProperty("name", equalTo("/SECRET/3"))
        ));

  }

  @Test
  public void findStartingWithPath_givenMultipleVersionsOfASecret() {
    saveNamedPassword(2000000000123L, "/DupSecret/1");
    saveNamedPassword(3000000000123L, "/DupSecret/1");
    saveNamedPassword(1000000000123L, "/DupSecret/1");

    List<SecretView> secrets = subject.findStartingWithPath("/dupsecret/");
    assertThat("should not return duplicate secret names",
        secrets.size(), equalTo(1));

    SecretView secret = secrets.get(0);
    assertThat("should return the most recent secret",
        secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
  }

  @Test
  public void findStartingWithPath_givenAPath_matchesFromTheStart() {
    setupTestFixtureForFindStartingWithPath();

    List<SecretView> secrets = subject.findStartingWithPath("Secret");

    assertThat(secrets.size(), equalTo(3));
    assertThat(secrets, not(contains(hasProperty("name", equalTo("/not/So/Secret")))));

    assertThat("appends trailing slash to path", secrets,
        not(contains(hasProperty("name", equalTo("/SECRETnotrailingslash")))));

    assertThat("appends trailing slash to path", secrets.get(0).getName().toLowerCase(),
        containsString("/secret/"));
  }

  @Test
  public void findAllPaths_returnsCompleteDirectoryStructure() {
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
    NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(
        namedCertificateSecretData);
    subject.save(namedCertificateSecret);

    assertThat(subject.findAllPaths(),
        equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
  }

  @Test
  public void findAllByName_whenProvidedAName_findsAllMatchingSecrets() {
    NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "/secret1");
    NamedPasswordSecret secret2 = saveNamedPassword(4000000000123L, "/seCret1");
    saveNamedPassword(3000000000123L, "/Secret2");

    List<NamedSecret> secrets = subject.findAllByName("/Secret1");
    assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
        hasProperty("uuid", equalTo(secret2.getUuid()))));

    secrets = subject.findAllByName("Secret1");
    assertThat("prepends slash to search if missing",
        secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
            hasProperty("uuid", equalTo(secret2.getUuid()))));

    assertThat("returns empty list when no secret matches",
        subject.findAllByName("does/NOT/exist"), empty());
  }

  @Test
  public void findEncryptedWithAvailableInactiveKeys() {
    UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();

    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(Arrays.asList(oldCanaryUuid));

    NamedPasswordSecret secret1 = saveNamedPassword(2000000000123L, "secret", oldCanaryUuid);
    NamedPasswordSecret secret2 = saveNamedPassword(3000000000123L, "ANOTHER", oldCanaryUuid);
    NamedPasswordSecret secret3 = saveNamedPassword(4000000000123L, "password", oldCanaryUuid);
    NamedPasswordSecret secret1Newer = saveNamedPassword(5000000000123L, "secret", oldCanaryUuid);

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


  private void setupTestFixtureForFindMostRecent() {
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

  }

  private void setupTestFixturesForFindContainingName(String valueName,
      String passwordName,
      String certificateName) {

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
    NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret(
        namedCertificateSecretData);
    subject.save(namedCertificateSecret);

    fakeTimeSetter.accept(3000000000123L);
    namedCertificateSecretData = new NamedCertificateSecretData(
        certificateName);
    namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedCertificateSecret = new NamedCertificateSecret(namedCertificateSecretData);
    subject.save(namedCertificateSecret);
  }

  private void setupTestFixtureForFindStartingWithPath() {
    saveNamedPassword(2000000000123L, "/secret/1");
    saveNamedPassword(3000000000123L, "/Secret/2");
    saveNamedPassword(1000000000123L, "/SECRET/3");
    saveNamedPassword(1000000000123L, "/not/So/Secret");
    saveNamedPassword(1000000000123L, "/SECRETnotrailingslash");
  }
}
