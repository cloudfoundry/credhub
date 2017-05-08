package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.CredentialData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.entity.SshCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.CredentialRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.FindCredentialResult;
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
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  CredentialNameDataService credentialNameDataService;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  CredentialDataService subject;

  private Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private UUID unknownCanaryUuid;
  private PasswordCredentialData passwordCredential2;
  private PasswordCredentialData namedPasswordCredential1;
  private ValueCredentialData valueCredentialData;

  @Before
  public void beforeEach() {
    fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);
    fakeTimeSetter.accept(345345L);

    activeCanaryUuid = encryptionKeyCanaryMapper.getActiveUuid();
    unknownCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();
  }

  @Test
  public void save_givenANewCredential_savesTheCredential() {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/my-credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);
    Credential savedCredential = subject.save(credential);

    assertNotNull(savedCredential);

    PasswordCredential savedPasswordCredential = (PasswordCredential) subject.findMostRecent("/my-credential");
    CredentialData credentialData = credentialRepository.findOneByUuid(savedCredential.getUuid());

    assertThat(savedPasswordCredential.getName(), equalTo(credential.getName()));
    assertThat(savedPasswordCredential.getUuid(), equalTo(credential.getUuid()));

    assertThat(credentialData.getCredentialName().getName(), equalTo("/my-credential"));
    assertThat(credentialData.getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void save_givenAnExistingCredential_updatesTheCredential() {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/my-credential-2");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);

    subject.save(credential);

    passwordCredentialData.setEncryptedValue("irynas-ninja-skills".getBytes());

    subject.save(credential);

    PasswordCredential savedPasswordCredential = (PasswordCredential) subject.findMostRecent("/my-credential-2");
    CredentialData credentialData = credentialRepository.findOneByUuid(savedPasswordCredential.getUuid());

    assertThat(credentialData.getCredentialName().getName(), equalTo("/my-credential-2"));
    assertThat(credentialData.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));
    assertThat(credentialData.getUuid(), equalTo(credential.getUuid()));
  }

  @Test
  public void save_givenANewCredential_generatesTheUuid() {
    SshCredential credential = new SshCredential("/my-credential-2").setPublicKey("fake-public-key");
    SshCredential savedCredential = subject.save(credential);

    UUID generatedUuid = savedCredential.getUuid();
    assertNotNull(generatedUuid);

    savedCredential.setPublicKey("updated-fake-public-key");
    savedCredential = subject.save(savedCredential);

    assertThat(savedCredential.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenACredentialWithALeadingSlash_savesWithTheLeadingSlash() {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/my/credential");
    PasswordCredential credentialWithLeadingSlash = new PasswordCredential(passwordCredentialData);

    subject.save(credentialWithLeadingSlash);

    Credential savedCredential = subject.findMostRecent("/my/credential");
    assertThat(savedCredential.getCredentialName().getName(), equalTo("/my/credential"));
  }

  @Test
  public void save_whenTheCredentialSavedWithoutAnEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    SshCredentialData sshCredentialData = new SshCredentialData("/my-credential");
    SshCredential credential = new SshCredential(sshCredentialData).setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void delete_onAnExistingCredential_returnsTrue() {
    credentialNameDataService.save(new CredentialName("/my-credential"));

    assertThat(subject.delete("/my-credential"), equalTo(true));
  }

  @Test
  public void delete_onACredentialName_deletesAllCredentialsWithTheName() {
    CredentialName credentialName = credentialNameDataService.save(new CredentialName("/my-credential"));

    PasswordCredentialData credentialData = new PasswordCredentialData();
    credentialData.setCredentialName(credentialName);
    credentialData.setEncryptionKeyUuid(activeCanaryUuid);
    credentialData.setEncryptedValue("credential-password".getBytes());
    subject.save(credentialData);

    credentialData = new PasswordCredentialData("/my-credential");
    credentialData.setCredentialName(credentialName);
    credentialData.setEncryptionKeyUuid(activeCanaryUuid);
    credentialData.setEncryptedValue("another password".getBytes());
    subject.save(credentialData);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");

    assertThat(subject.findAllByName("/my-credential"), hasSize(0));
    assertNull(credentialNameDataService.find("/my-credential"));
  }

  @Test
  public void delete_givenACredentialNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
    CredentialName credentialName = credentialNameDataService.save(new CredentialName("/my-credential"));

    PasswordCredentialData credential = new PasswordCredentialData();
    credential.setCredentialName(credentialName);
    credential.setEncryptionKeyUuid(activeCanaryUuid);
    credential.setEncryptedValue("credential-password".getBytes());
    subject.save(credential);

    credential = new PasswordCredentialData();
    credential.setCredentialName(credentialName);
    credential.setEncryptionKeyUuid(activeCanaryUuid);
    credential.setEncryptedValue("another password".getBytes());

    subject.save(credential);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("MY-CREDENTIAL");

    assertThat(subject.findAllByName("/my-credential"), empty());
  }

  @Test
  public void delete_givenACredentialNameWithoutALeadingSlash_deletesTheCredentialAnyway() {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/my/credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);
    subject.save(credential);

    subject.delete("my/credential");

    assertThat(subject.findAllByName("/my/credential"), hasSize(0));
  }

  @Test
  public void delete_givenANonExistentCredentialName_returnsFalse() {
    assertThat(subject.delete("/does/not/exist"), equalTo(false));
  }

  @Test
  public void findMostRecent_givenACredentialNameWithoutVersions_returnsNull() {
    credentialNameDataService.save(new CredentialName("/my-unused-CREDENTIAL"));

    assertNull(subject.findMostRecent("/my-unused-CREDENTIAL"));
  }

  @Test
  public void findMostRecent_givenACredentialName_returnsMostRecentCredentialWithoutCaseSensitivity() {
    setupTestFixtureForFindMostRecent();

    PasswordCredential passwordCredential = (PasswordCredential) subject
        .findMostRecent("/my-credential");
    assertThat(passwordCredential.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(passwordCredential2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findMostRecent_givenACredentialName_returnsTheMostRecentCredentialIgnoringTheLeadingSlash() {
    setupTestFixtureForFindMostRecent();

    PasswordCredential passwordCredential = (PasswordCredential) subject
        .findMostRecent("my-credential");
    assertThat(passwordCredential.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(passwordCredential2.getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findByUuid_givenAUuid_findsTheCredential() {
    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/my-credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);
    PasswordCredential savedCredential = subject.save(credential);

    assertNotNull(savedCredential.getUuid());
    PasswordCredential oneByUuid = (PasswordCredential) subject
        .findByUuid(savedCredential.getUuid().toString());
    assertThat(oneByUuid.getName(), equalTo("/my-credential"));
    assertThat(passwordCredentialData.getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void findContainingName_givenACredentialName_returnsCredentialsInReverseChronologicalOrder() {
    String valueName = "/value.Credential";
    String passwordName = "/password/Credential";
    String certificateName = "/certif/ic/atecredential";

    setupTestFixturesForFindContainingName(valueName, passwordName, certificateName);

    assertThat(subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo(certificateName)),
        hasProperty("name", equalTo(valueName)),
        hasProperty("name", equalTo(passwordName))));

    ValueCredential valueCredential = (ValueCredential) subject.findMostRecent("value.Credential");
    valueCredentialData.setEncryptedValue("new-encrypted-value".getBytes());
    subject.save(valueCredential);

    assertThat("The credentials are ordered by versionCreatedAt",
        subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo(certificateName)),
            hasProperty("name", equalTo(valueName)),
            hasProperty("name", equalTo(passwordName))
        ));
  }

  @Test
  public void findContainingName_whenThereAreMultipleVerionsOfACredential() {

    savePassword(2000000000123L, "foo/DUPLICATE");
    savePassword(1000000000123L, "foo/DUPLICATE");
    savePassword(3000000000123L, "bar/duplicate");
    savePassword(4000000000123L, "bar/duplicate");

    List<FindCredentialResult> credentials = subject.findContainingName("DUP");
    assertThat("should only return unique credential names", credentials.size(), equalTo(2));

    FindCredentialResult credential = credentials.get(0);
    assertThat(credential.getName(), equalTo("/bar/duplicate"));
    assertThat("should return the most recently created version",
        credential.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(4000000000123L)));

    credential = credentials.get(1);
    assertThat(credential.getName(), equalTo("/foo/DUPLICATE"));
    assertThat("should return the most recently created version",
        credential.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(2000000000123L)));
  }

  @Test
  public void findStartingWithPath_whenProvidedAPath_returnsTheListOfOrderedCredentials() {
    setupTestFixtureForFindStartingWithPath();

    List<FindCredentialResult> credentials = subject.findStartingWithPath("Credential/");

    assertThat(credentials.size(), equalTo(3));
    assertThat(credentials, IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo("/Credential/2")),
        hasProperty("name", equalTo("/credential/1")),
        hasProperty("name", equalTo("/CREDENTIAL/3"))
    ));
    assertThat(
        "should return a list of credentials in chronological order that start with a given string",
        credentials, not(contains(hasProperty("notSoSecret"))));

    PasswordCredential passwordCredential = (PasswordCredential) subject
        .findMostRecent("credential/1");
    passwordCredential.setPasswordAndGenerationParameters("new-password", null);
    subject.save(passwordCredential);
    credentials = subject.findStartingWithPath("Credential/");
    assertThat("should return credentials in order by version_created_at, not updated_at",
        credentials, IsIterableContainingInOrder.contains(
            hasProperty("name", equalTo("/Credential/2")),
            hasProperty("name", equalTo("/credential/1")),
            hasProperty("name", equalTo("/CREDENTIAL/3"))
        ));

  }

  @Test
  public void findStartingWithPath_givenMultipleVersionsOfACredential() {
    savePassword(2000000000123L, "/DupSecret/1");
    savePassword(3000000000123L, "/DupSecret/1");
    savePassword(1000000000123L, "/DupSecret/1");

    List<FindCredentialResult> credentials = subject.findStartingWithPath("/dupsecret/");
    assertThat("should not return duplicate credential names",
        credentials.size(), equalTo(1));

    FindCredentialResult credential = credentials.get(0);
    assertThat("should return the most recent credential",
        credential.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
  }

  @Test
  public void findStartingWithPath_givenAPath_matchesFromTheStart() {
    setupTestFixtureForFindStartingWithPath();

    List<FindCredentialResult> credentials = subject.findStartingWithPath("Credential");

    assertThat(credentials.size(), equalTo(3));
    assertThat(credentials, not(contains(hasProperty("name", equalTo("/not/So/Credential")))));

    assertThat("appends trailing slash to path", credentials,
        not(contains(hasProperty("name", equalTo("/CREDENTIALnotrailingslash")))));

    assertThat("appends trailing slash to path", credentials.get(0).getName().toLowerCase(),
        containsString("/credential/"));
  }

  @Test
  public void findAllPaths_returnsCompleteDirectoryStructure() {
    String valueOther = "/fubario";
    String valueName = "/value/Credential";
    String passwordName = "/password/Credential";
    String certificateName = "/certif/ic/ateCredential";

    ValueCredentialData valueCredentialData = new ValueCredentialData(valueOther);
    valueCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    ValueCredential valueCredential = new ValueCredential(valueCredentialData);
    subject.save(valueCredential);

    valueCredentialData = new ValueCredentialData(valueName);
    valueCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    valueCredential = new ValueCredential(valueCredentialData);
    subject.save(valueCredential);

    PasswordCredentialData passwordCredentialData = new PasswordCredentialData(passwordName);
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    PasswordCredential passwordCredential = new PasswordCredential(passwordCredentialData);
    subject.save(passwordCredential);

    CertificateCredentialData certificateCredentialData =
        new CertificateCredentialData(certificateName);
    certificateCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    CertificateCredential certificateCredential = new CertificateCredential(
        certificateCredentialData);
    subject.save(certificateCredential);

    assertThat(subject.findAllPaths(),
        equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
  }

  @Test
  public void findAllByName_whenProvidedAName_findsAllMatchingCredentials() {
    PasswordCredential credential1 = savePassword(2000000000123L, "/secret1");
    PasswordCredential credential2 = savePassword(4000000000123L, "/seCret1");
    savePassword(3000000000123L, "/Secret2");

    List<Credential> credentials = subject.findAllByName("/Secret1");
    assertThat(credentials, containsInAnyOrder(hasProperty("uuid", equalTo(credential1.getUuid())),
        hasProperty("uuid", equalTo(credential2.getUuid()))));

    credentials = subject.findAllByName("Secret1");
    assertThat("prepends slash to search if missing",
        credentials, containsInAnyOrder(hasProperty("uuid", equalTo(credential1.getUuid())),
            hasProperty("uuid", equalTo(credential2.getUuid()))));

    assertThat("returns empty list when no credential matches",
        subject.findAllByName("does/NOT/exist"), empty());
  }

  @Test
  public void findEncryptedWithAvailableInactiveKeys() {
    UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();

    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(Arrays.asList(oldCanaryUuid));

    PasswordCredential credential1 = savePassword(2000000000123L, "credential", oldCanaryUuid);
    PasswordCredential credential2 = savePassword(3000000000123L, "ANOTHER", oldCanaryUuid);
    PasswordCredential credential3 = savePassword(4000000000123L, "password", oldCanaryUuid);
    PasswordCredential credential1Newer = savePassword(5000000000123L, "credential", oldCanaryUuid);

    PasswordCredential credentialEncryptedWithActiveKey = savePassword(3000000000123L,
        "ANOTHER", activeCanaryUuid);
    PasswordCredential newerCredentialEncryptedWithActiveKey = savePassword(
        4000000000123L, "ANOTHER", activeCanaryUuid);
    PasswordCredential credentialEncryptedWithUnknownKey = savePassword(4000000000123L,
        "ANOTHER", unknownCanaryUuid);

    final Slice<Credential> credentials = subject.findEncryptedWithAvailableInactiveKey();
    List<UUID> credentialUuids = credentials.getContent().stream().map(credential -> credential.getUuid())
        .collect(Collectors.toList());

    assertThat(credentialUuids, not(contains(credentialEncryptedWithActiveKey.getUuid())));
    assertThat(credentialUuids, not(contains(newerCredentialEncryptedWithActiveKey.getUuid())));

    assertThat(credentialUuids, not(contains(credentialEncryptedWithUnknownKey.getUuid())));

    assertThat(credentialUuids,
        containsInAnyOrder(credential1.getUuid(), credential2.getUuid(), credential3.getUuid(),
            credential1Newer.getUuid()));
  }


  private PasswordCredential savePassword(long timeMillis, String name, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName == null) {
      credentialName = credentialNameDataService.save(new CredentialName(name));
    }
    PasswordCredentialData credentialObject = new PasswordCredentialData();
    credentialObject.setCredentialName(credentialName);
    credentialObject.setEncryptionKeyUuid(canaryUuid);
    return subject.save(credentialObject);
  }

  private PasswordCredential savePassword(long timeMillis, String credentialName) {
    return savePassword(timeMillis, credentialName, activeCanaryUuid);
  }


  private void setupTestFixtureForFindMostRecent() {
    CredentialName credentialName = credentialNameDataService.save(new CredentialName("/my-CREDENTIAL"));

    namedPasswordCredential1 = new PasswordCredentialData();
    namedPasswordCredential1.setCredentialName(credentialName);
    namedPasswordCredential1.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordCredential1.setEncryptedValue("/my-old-password".getBytes());

    passwordCredential2 = new PasswordCredentialData();
    passwordCredential2.setCredentialName(credentialName);
    passwordCredential2.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredential2.setEncryptedValue("/my-new-password".getBytes());

    subject.save(namedPasswordCredential1);
    fakeTimeSetter.accept(345346L); // 1 second later
    subject.save(passwordCredential2);

  }

  private void setupTestFixturesForFindContainingName(String valueName,
      String passwordName,
      String certificateName) {

    fakeTimeSetter.accept(2000000000123L);
    valueCredentialData = new ValueCredentialData(valueName);
    valueCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    ValueCredential namedValueCredential = new ValueCredential(valueCredentialData);
    subject.save(namedValueCredential);

    PasswordCredentialData passwordCredentialData = new PasswordCredentialData("/mySe.cret");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    PasswordCredential namedPasswordCredential = new PasswordCredential(passwordCredentialData);
    subject.save(namedValueCredential);

    fakeTimeSetter.accept(1000000000123L);
    passwordCredentialData = new PasswordCredentialData(passwordName);
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordCredential = new PasswordCredential(passwordCredentialData);
    subject.save(namedPasswordCredential);

    CertificateCredentialData certificateCredentialData = new CertificateCredentialData(
        "/myseecret");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    CertificateCredential certificateCredential = new CertificateCredential(
        certificateCredentialData);
    subject.save(certificateCredential);

    fakeTimeSetter.accept(3000000000123L);
    certificateCredentialData = new CertificateCredentialData(
        certificateName);
    certificateCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    certificateCredential = new CertificateCredential(certificateCredentialData);
    subject.save(certificateCredential);
  }

  private void setupTestFixtureForFindStartingWithPath() {
    savePassword(2000000000123L, "/credential/1");
    savePassword(3000000000123L, "/Credential/2");
    savePassword(1000000000123L, "/CREDENTIAL/3");
    savePassword(1000000000123L, "/not/So/Credential");
    savePassword(1000000000123L, "/CREDENTIALnotrailingslash");
  }
}
