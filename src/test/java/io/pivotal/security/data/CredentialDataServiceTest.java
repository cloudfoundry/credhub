package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.repository.CredentialRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.CredentialView;
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
public class CredentialDataServiceTest {

  @Autowired
  CredentialRepository credentialRepository;

  @Autowired
  CredentialNameRepository nameRepository;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  CredentialNameRepository credentialNameRepository;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  CredentialDataService subject;

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
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-credential");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential secret = new PasswordCredential(namedPasswordSecretData);
    Credential savedSecret = subject.save(secret);

    assertNotNull(savedSecret);

    PasswordCredential savedPasswordSecret = (PasswordCredential) subject.findMostRecent("/my-credential");
    NamedSecretData secretData = credentialRepository.findOneByUuid(savedSecret.getUuid());

    assertThat(savedPasswordSecret.getName(), equalTo(secret.getName()));
    assertThat(savedPasswordSecret.getUuid(), equalTo(secret.getUuid()));

    assertThat(secretData.getCredentialName().getName(), equalTo("/my-credential"));
    assertThat(secretData.getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void save_givenAnExistingSecret_updatesTheSecret() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-credential-2");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential secret = new PasswordCredential(namedPasswordSecretData);

    subject.save(secret);

    namedPasswordSecretData.setEncryptedValue("irynas-ninja-skills".getBytes());

    subject.save(secret);

    PasswordCredential savedPasswordSecret = (PasswordCredential) subject.findMostRecent("/my-credential-2");
    NamedSecretData secretData = credentialRepository.findOneByUuid(savedPasswordSecret.getUuid());

    assertThat(secretData.getCredentialName().getName(), equalTo("/my-credential-2"));
    assertThat(secretData.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));
    assertThat(secretData.getUuid(), equalTo(secret.getUuid()));
  }

  @Test
  public void save_givenANewSecret_generatesTheUuid() {
    SshCredential secret = new SshCredential("/my-credential-2").setPublicKey("fake-public-key");
    SshCredential savedSecret = subject.save(secret);

    UUID generatedUuid = savedSecret.getUuid();
    assertNotNull(generatedUuid);

    savedSecret.setPublicKey("updated-fake-public-key");
    savedSecret = subject.save(savedSecret);

    assertThat(savedSecret.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenASecretWithALeadingSlash_savesWithTheLeadingSlash() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/credential");
    PasswordCredential secretWithLeadingSlash = new PasswordCredential(namedPasswordSecretData);

    subject.save(secretWithLeadingSlash);

    Credential savedSecret = subject.findMostRecent("/my/credential");
    assertThat(savedSecret.getCredentialName().getName(), equalTo("/my/credential"));
  }

  @Test
  public void save_whenTheSecretSavedWithoutAnEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    NamedSshSecretData namedSshSecretData = new NamedSshSecretData("/my-credential");
    SshCredential secret = new SshCredential(namedSshSecretData).setPublicKey("fake-public-key");
    subject.save(secret);

    assertThat(namedSshSecretData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void delete_onAnExistingSecret_returnsTrue() {
    credentialNameRepository.saveAndFlush(new CredentialName("/my-credential"));

    assertThat(subject.delete("/my-credential"), equalTo(true));
  }

  @Test
  public void delete_onACredentialName_deletesAllSecretsWithTheName() {
    CredentialName credentialName = credentialNameRepository.saveAndFlush(new CredentialName("/my-credential"));

    NamedPasswordSecretData secret = new NamedPasswordSecretData();
    secret.setCredentialName(credentialName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("credential-password".getBytes());
    subject.save(secret);

    secret = new NamedPasswordSecretData("/my-credential");
    secret.setCredentialName(credentialName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("another password".getBytes());
    subject.save(secret);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");

    assertThat(subject.findAllByName("/my-credential"), hasSize(0));
    assertNull(nameRepository.findOneByNameIgnoreCase("/my-credential"));
  }

  @Test
  public void delete_givenACredentialNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
    CredentialName credentialName = credentialNameRepository.saveAndFlush(new CredentialName("/my-credential"));

    NamedPasswordSecretData secret = new NamedPasswordSecretData();
    secret.setCredentialName(credentialName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("credential-password".getBytes());
    subject.save(secret);

    secret = new NamedPasswordSecretData();
    secret.setCredentialName(credentialName);
    secret.setEncryptionKeyUuid(activeCanaryUuid);
    secret.setEncryptedValue("another password".getBytes());

    subject.save(secret);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("MY-CREDENTIAL");

    assertThat(subject.findAllByName("/my-credential"), empty());
  }

  @Test
  public void delete_givenACredentialNameWithoutALeadingSlash_deletesTheSecretAnyway() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my/credential");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential secret = new PasswordCredential(namedPasswordSecretData);
    subject.save(secret);

    subject.delete("my/credential");

    assertThat(subject.findAllByName("/my/credential"), hasSize(0));
  }

  @Test
  public void delete_givenANonExistentCredentialName_returnsFalse() {
    assertThat(subject.delete("/does/not/exist"), equalTo(false));
  }

  @Test
  public void findMostRecent_givenACredentialNameWithoutVersions_returnsNull() {
    credentialNameRepository.saveAndFlush(new CredentialName("/my-unused-CREDENTIAL"));

    assertNull(subject.findMostRecent("/my-unused-CREDENTIAL"));
  }

  @Test
  public void findMostRecent_givenACredentialName_returnsMostRecentSecretWithoutCaseSensitivity() {
    setupTestFixtureForFindMostRecent();

    PasswordCredential passwordSecret = (PasswordCredential) subject
        .findMostRecent("/my-credential");
    assertThat(passwordSecret.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findMostRecent_givenACredentialName_returnsTheMostRecentSecretIgnoringTheLeadingSlash() {
    setupTestFixtureForFindMostRecent();

    PasswordCredential passwordSecret = (PasswordCredential) subject
        .findMostRecent("my-credential");
    assertThat(passwordSecret.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(namedPasswordSecret2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findByUuid_givenAUuid_findsTheSecret() {
    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/my-credential");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecretData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential secret = new PasswordCredential(namedPasswordSecretData);
    PasswordCredential savedSecret = subject.save(secret);

    assertNotNull(savedSecret.getUuid());
    PasswordCredential oneByUuid = (PasswordCredential) subject
        .findByUuid(savedSecret.getUuid().toString());
    assertThat(oneByUuid.getName(), equalTo("/my-credential"));
    assertThat(namedPasswordSecretData.getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void findContainingName_givenACredentialName_returnsSecretsInReverseChronologicalOrder() {
    String valueName = "/value.Credential";
    String passwordName = "/password/Credential";
    String certificateName = "/certif/ic/atecredential";

    setupTestFixturesForFindContainingName(valueName, passwordName, certificateName);

    assertThat(subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo(certificateName)),
        hasProperty("name", equalTo(valueName)),
        hasProperty("name", equalTo(passwordName))));

    ValueCredential valueSecret = (ValueCredential) subject.findMostRecent("value.Credential");
    namedValueSecretData.setEncryptedValue("new-encrypted-value".getBytes());
    subject.save(valueSecret);

    assertThat("The secrets are ordered by versionCreatedAt",
        subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
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

    List<CredentialView> secrets = subject.findContainingName("DUP");
    assertThat("should only return unique credential names", secrets.size(), equalTo(2));

    CredentialView secret = secrets.get(0);
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

    List<CredentialView> secrets = subject.findStartingWithPath("Credential/");

    assertThat(secrets.size(), equalTo(3));
    assertThat(secrets, IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo("/Credential/2")),
        hasProperty("name", equalTo("/credential/1")),
        hasProperty("name", equalTo("/CREDENTIAL/3"))
    ));
    assertThat(
        "should return a list of secrets in chronological order that start with a given string",
        secrets, not(contains(hasProperty("notSoSecret"))));

    PasswordCredential passwordSecret = (PasswordCredential) subject
        .findMostRecent("credential/1");
    passwordSecret.setPasswordAndGenerationParameters("new-password", null);
    subject.save(passwordSecret);
    secrets = subject.findStartingWithPath("Credential/");
    assertThat("should return secrets in order by version_created_at, not updated_at",
        secrets, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Credential/2")),
            hasProperty("name", equalTo("/credential/1")),
            hasProperty("name", equalTo("/CREDENTIAL/3"))
        ));

  }

  @Test
  public void findStartingWithPath_givenMultipleVersionsOfASecret() {
    saveNamedPassword(2000000000123L, "/DupSecret/1");
    saveNamedPassword(3000000000123L, "/DupSecret/1");
    saveNamedPassword(1000000000123L, "/DupSecret/1");

    List<CredentialView> secrets = subject.findStartingWithPath("/dupsecret/");
    assertThat("should not return duplicate credential names",
        secrets.size(), equalTo(1));

    CredentialView secret = secrets.get(0);
    assertThat("should return the most recent credential",
        secret.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
  }

  @Test
  public void findStartingWithPath_givenAPath_matchesFromTheStart() {
    setupTestFixtureForFindStartingWithPath();

    List<CredentialView> secrets = subject.findStartingWithPath("Credential");

    assertThat(secrets.size(), equalTo(3));
    assertThat(secrets, not(contains(hasProperty("name", equalTo("/not/So/Credential")))));

    assertThat("appends trailing slash to path", secrets,
        not(contains(hasProperty("name", equalTo("/CREDENTIALnotrailingslash")))));

    assertThat("appends trailing slash to path", secrets.get(0).getName().toLowerCase(),
        containsString("/credential/"));
  }

  @Test
  public void findAllPaths_returnsCompleteDirectoryStructure() {
    String valueOther = "/fubario";
    String valueName = "/value/Credential";
    String passwordName = "/password/Credential";
    String certificateName = "/certif/ic/ateCredential";

    NamedValueSecretData namedValueSecretData = new NamedValueSecretData(valueOther);
    namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    ValueCredential namedValueSecret = new ValueCredential(namedValueSecretData);
    subject.save(namedValueSecret);

    namedValueSecretData = new NamedValueSecretData(valueName);
    namedValueSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedValueSecret = new ValueCredential(namedValueSecretData);
    subject.save(namedValueSecret);

    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData(passwordName);
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    PasswordCredential namedPasswordSecret = new PasswordCredential(namedPasswordSecretData);
    subject.save(namedPasswordSecret);

    NamedCertificateSecretData namedCertificateSecretData =
        new NamedCertificateSecretData(certificateName);
    namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    CertificateCredential namedCertificateSecret = new CertificateCredential(
        namedCertificateSecretData);
    subject.save(namedCertificateSecret);

    assertThat(subject.findAllPaths(),
        equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
  }

  @Test
  public void findAllByName_whenProvidedAName_findsAllMatchingSecrets() {
    PasswordCredential secret1 = saveNamedPassword(2000000000123L, "/secret1");
    PasswordCredential secret2 = saveNamedPassword(4000000000123L, "/seCret1");
    saveNamedPassword(3000000000123L, "/Secret2");

    List<Credential> secrets = subject.findAllByName("/Secret1");
    assertThat(secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
        hasProperty("uuid", equalTo(secret2.getUuid()))));

    secrets = subject.findAllByName("Secret1");
    assertThat("prepends slash to search if missing",
        secrets, containsInAnyOrder(hasProperty("uuid", equalTo(secret1.getUuid())),
            hasProperty("uuid", equalTo(secret2.getUuid()))));

    assertThat("returns empty list when no credential matches",
        subject.findAllByName("does/NOT/exist"), empty());
  }

  @Test
  public void findEncryptedWithAvailableInactiveKeys() {
    UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();

    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(Arrays.asList(oldCanaryUuid));

    PasswordCredential secret1 = saveNamedPassword(2000000000123L, "credential", oldCanaryUuid);
    PasswordCredential secret2 = saveNamedPassword(3000000000123L, "ANOTHER", oldCanaryUuid);
    PasswordCredential secret3 = saveNamedPassword(4000000000123L, "password", oldCanaryUuid);
    PasswordCredential secret1Newer = saveNamedPassword(5000000000123L, "credential", oldCanaryUuid);

    PasswordCredential secretEncryptedWithActiveKey = saveNamedPassword(3000000000123L,
        "ANOTHER", activeCanaryUuid);
    PasswordCredential newerSecretEncryptedWithActiveKey = saveNamedPassword(
        4000000000123L, "ANOTHER", activeCanaryUuid);
    PasswordCredential secretEncryptedWithUnknownKey = saveNamedPassword(4000000000123L,
        "ANOTHER", unknownCanaryUuid);

    final Slice<Credential> secrets = subject.findEncryptedWithAvailableInactiveKey();
    List<UUID> secretUuids = secrets.getContent().stream().map(secret -> secret.getUuid())
        .collect(Collectors.toList());

    assertThat(secretUuids, not(contains(secretEncryptedWithActiveKey.getUuid())));
    assertThat(secretUuids, not(contains(newerSecretEncryptedWithActiveKey.getUuid())));

    assertThat(secretUuids, not(contains(secretEncryptedWithUnknownKey.getUuid())));

    assertThat(secretUuids,
        containsInAnyOrder(secret1.getUuid(), secret2.getUuid(), secret3.getUuid(),
            secret1Newer.getUuid()));
  }


  private PasswordCredential saveNamedPassword(long timeMillis, String name, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    CredentialName credentialName = credentialNameRepository
        .findOneByNameIgnoreCase(StringUtils.prependIfMissing(name, "/"));
    if (credentialName == null) {
      credentialName = credentialNameRepository.saveAndFlush(new CredentialName(name));
    }
    NamedPasswordSecretData secretObject = new NamedPasswordSecretData();
    secretObject.setCredentialName(credentialName);
    secretObject.setEncryptionKeyUuid(canaryUuid);
    return subject.save(secretObject);
  }

  private PasswordCredential saveNamedPassword(long timeMillis, String credentialName) {
    return saveNamedPassword(timeMillis, credentialName, activeCanaryUuid);
  }


  private void setupTestFixtureForFindMostRecent() {
    CredentialName credentialName = credentialNameRepository.saveAndFlush(new CredentialName("/my-CREDENTIAL"));

    namedPasswordSecret1 = new NamedPasswordSecretData();
    namedPasswordSecret1.setCredentialName(credentialName);
    namedPasswordSecret1.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecret1.setEncryptedValue("/my-old-password".getBytes());

    namedPasswordSecret2 = new NamedPasswordSecretData();
    namedPasswordSecret2.setCredentialName(credentialName);
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
    ValueCredential namedValueSecret = new ValueCredential(namedValueSecretData);
    subject.save(namedValueSecret);

    NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData("/mySe.cret");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    PasswordCredential namedPasswordSecret = new PasswordCredential(namedPasswordSecretData);
    subject.save(namedValueSecret);

    fakeTimeSetter.accept(1000000000123L);
    namedPasswordSecretData = new NamedPasswordSecretData(passwordName);
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordSecret = new PasswordCredential(namedPasswordSecretData);
    subject.save(namedPasswordSecret);

    NamedCertificateSecretData namedCertificateSecretData = new NamedCertificateSecretData(
        "/myseecret");
    namedPasswordSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    CertificateCredential namedCertificateSecret = new CertificateCredential(
        namedCertificateSecretData);
    subject.save(namedCertificateSecret);

    fakeTimeSetter.accept(3000000000123L);
    namedCertificateSecretData = new NamedCertificateSecretData(
        certificateName);
    namedCertificateSecretData.setEncryptionKeyUuid(activeCanaryUuid);
    namedCertificateSecret = new CertificateCredential(namedCertificateSecretData);
    subject.save(namedCertificateSecret);
  }

  private void setupTestFixtureForFindStartingWithPath() {
    saveNamedPassword(2000000000123L, "/credential/1");
    saveNamedPassword(3000000000123L, "/Credential/2");
    saveNamedPassword(1000000000123L, "/CREDENTIAL/3");
    saveNamedPassword(1000000000123L, "/not/So/Credential");
    saveNamedPassword(1000000000123L, "/CREDENTIALnotrailingslash");
  }
}
