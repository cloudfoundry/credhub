package org.cloudfoundry.credhub.services;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.MaximumSizeException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.repositories.CredentialRepository;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.repositories.EncryptedValueRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.utils.DatabaseUtilities;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.cloudfoundry.credhub.views.FindCredentialResult;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.credhub.utils.SpringUtilities.activeProfilesString;
import static org.cloudfoundry.credhub.utils.SpringUtilities.unitTestPostgresProfile;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class DefaultCredentialVersionDataServiceTest {

  @Value("${spring.profiles.active}")
  private String activeSpringProfile;

  @Autowired
  private CredentialVersionRepository credentialVersionRepository;

  @Autowired
  private CredentialRepository credentialRepository;

  @Autowired
  private EncryptedValueRepository encryptedValueRepository;

  @Autowired
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  private CredentialDataService credentialDataService;

  @Autowired
  private EncryptionKeySet keySet;

  @MockBean
  private CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  private CredentialVersionDataService subject;

  @Autowired
  private CEFAuditRecord cefAuditRecord;

  @Autowired
  private Encryptor encryptor;

  private JsonObjectMapper objectMapper;

  private Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private PasswordCredentialVersionData passwordCredential2;
  private PasswordCredentialVersionData namedPasswordCredential1;
  private ValueCredentialVersionData valueCredentialData;

  @Before
  public void beforeEach() {
    fakeTimeSetter = TestHelper.mockOutCurrentTimeProvider(mockCurrentTimeProvider);
    fakeTimeSetter.accept(345345L);

    objectMapper = new JsonObjectMapper();
    activeCanaryUuid = keySet.getActive().getUuid();
  }

  @Test
  public void save_givenANewCredential_savesTheCredential() {
    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(
      activeCanaryUuid,
      "credential-password",
      ""
    ));
    final PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);
    credential.setEncryptor(encryptor);
    final CredentialVersion savedCredentialVersion = subject.save(credential);

    assertNotNull(savedCredentialVersion);

    final PasswordCredentialVersion savedPasswordCredential = (PasswordCredentialVersion) subject
      .findMostRecent("/my-credential");
    final CredentialVersionData credentialVersionData = credentialVersionRepository
      .findOneByUuid(savedCredentialVersion.getUuid());

    assertThat(savedPasswordCredential.getName(), equalTo(credential.getName()));
    assertThat(savedPasswordCredential.getUuid(), equalTo(credential.getUuid()));

    assertThat(credentialVersionData.getCredential().getName(), equalTo("/my-credential"));
    assertThat(credentialVersionData.getEncryptedValueData().getEncryptedValue(),
      equalTo("credential-password".getBytes(UTF_8)));
  }

  @Test
  public void save_givenAnExistingCredential_updatesTheCredential() {
    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential-2");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(
      activeCanaryUuid,
      "credential-password",
      "nonce"
    ));
    final PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credential);

    passwordCredentialData.getEncryptedValueData().setEncryptedValue("irynas-ninja-skills".getBytes(UTF_8));

    subject.save(credential);

    final PasswordCredentialVersion savedPasswordCredential = (PasswordCredentialVersion) subject
      .findMostRecent("/my-credential-2");
    final CredentialVersionData credentialVersionData = credentialVersionRepository
      .findOneByUuid(savedPasswordCredential.getUuid());

    assertThat(credentialVersionData.getCredential().getName(), equalTo("/my-credential-2"));
    assertThat(credentialVersionData.getEncryptedValueData().getEncryptedValue(),
      equalTo("irynas-ninja-skills".getBytes(UTF_8)));
    assertThat(credentialVersionData.getUuid(), equalTo(credential.getUuid()));
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_givenAnExistingCredential_throwsExceptionIfTypeMismatch() {

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue(new byte[]{});
    encryptedValueA.setNonce(new byte[]{});

    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential-3");
    passwordCredentialData.setEncryptedValueData(encryptedValueA);
    final PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credential);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("some value".getBytes(UTF_8));

    final ValueCredentialVersionData newCredentialData = new ValueCredentialVersionData("test-credential");
    newCredentialData.setEncryptedValueData(encryptedValueB);
    newCredentialData.setCredential(passwordCredentialData.getCredential());
    final ValueCredentialVersion newCredential = new ValueCredentialVersion(newCredentialData);

    subject.save(newCredential);
  }

  @Test
  public void save_givenANewCredential_generatesTheUuid() {
    final SshCredentialVersion credential = new SshCredentialVersion("/my-credential-2");
    credential.setEncryptor(encryptor);
    credential.setPrivateKey("privatekey");
    credential.setPublicKey("fake-public-key");
    SshCredentialVersion savedCredential = (SshCredentialVersion) subject.save(credential);

    final UUID generatedUuid = savedCredential.getUuid();
    assertNotNull(generatedUuid);

    savedCredential.setPublicKey("updated-fake-public-key");
    savedCredential = (SshCredentialVersion) subject.save(savedCredential);

    assertThat(savedCredential.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenACredentialWithALeadingSlash_savesWithTheLeadingSlash() {
    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my/credential");
    final PasswordCredentialVersion credentialWithLeadingSlash = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credentialWithLeadingSlash);

    final CredentialVersion savedCredentialVersion = subject.findMostRecent("/my/credential");
    assertThat(savedCredentialVersion.getCredential().getName(), equalTo("/my/credential"));
  }

  @Test
  public void save_whenTheCredentialSavedWithEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    final SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("/my-credential");
    final SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData);
    credential.setEncryptor(encryptor);
    credential.setPrivateKey("private-key");
    credential.setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void save_whenTheCredentialSavedWithoutEncryptedValueSet_doesNotSetTheMasterEncryptionKeyUuid() {
    final SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("/my-credential");
    final SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData);
    credential.setEncryptor(encryptor);
    credential.setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), nullValue());
  }

  @Test
  public void save_whenGivenCredentialWithMetadata() {
    final ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData("/my-credential");
    final ValueCredentialVersion credential = new ValueCredentialVersion(valueCredentialData);

    JsonNode metadata = null;
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }
    credential.setEncryptor(encryptor);
    credential.setMetadata(metadata);
    subject.save(credential);

    assertThat(credential.getMetadata(), equalTo(metadata));
  }

  @Test
  public void delete_onAnExistingCredential_returnsTrue() {
    credentialDataService.save(new Credential("/my-credential"));

    assertThat(subject.delete("/my-credential"), equalTo(true));
  }

  @Test
  @Transactional(propagation = Propagation.NEVER)
  public void delete_onACredentialName_deletesAllCredentialsWithTheName() {
    long nEncryptedValuesPre = encryptedValueRepository.count();
    final Credential credential = credentialDataService
      .save(new Credential("/my-credential"));

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue("credential-password".getBytes(UTF_8));
    encryptedValueA.setNonce("nonce".getBytes(UTF_8));

    final PasswordCredentialVersionData credentialDataA = new PasswordCredentialVersionData("test-password");
    credentialDataA.setCredential(credential);
    credentialDataA.setEncryptedValueData(encryptedValueA);
    subject.save(credentialDataA);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("another password".getBytes(UTF_8));
    encryptedValueB.setNonce("nonce".getBytes(UTF_8));

    final PasswordCredentialVersionData credentialDataB = new PasswordCredentialVersionData("/my-credential");
    credentialDataB.setCredential(credential);
    credentialDataB.setEncryptedValueData(encryptedValueB);
    subject.save(credentialDataB);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");

    assertThat(subject.findAllByName("/my-credential"), hasSize(0));
    assertNull(credentialDataService.find("/my-credential"));
    assertEquals("Associated encryptedValues are deleted when password credential is deleted",
            nEncryptedValuesPre, encryptedValueRepository.count());
  }

  @Test
  @Transactional(propagation = Propagation.NEVER)
  public void delete_givenACredentialNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
    long nEncryptedValuesPre = encryptedValueRepository.count();
    final Credential credentialName = credentialDataService
      .save(new Credential("/my-credential"));

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue("credential-password".getBytes(UTF_8));
    encryptedValueA.setNonce(new byte[]{});

    PasswordCredentialVersionData credential = new PasswordCredentialVersionData("test-password");
    credential.setCredential(credentialName);
    credential.setEncryptedValueData(encryptedValueA);
    subject.save(credential);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("another password".getBytes(UTF_8));
    encryptedValueB.setNonce(new byte[]{});

    credential = new PasswordCredentialVersionData("test-password");
    credential.setCredential(credentialName);
    credential.setEncryptedValueData(encryptedValueB);

    subject.save(credential);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/MY-CREDENTIAL");

    assertThat(subject.findAllByName("/my-credential"), empty());
    assertEquals("Associated encryptedValues are deleted when password credential is deleted",
            nEncryptedValuesPre, encryptedValueRepository.count());
  }

  @Test
  @Transactional(propagation = Propagation.NEVER)
  public void delete_UserTypeCredential() {
    long nEncryptedValuesPre = encryptedValueRepository.count();
    final Credential credentialName = credentialDataService.save(
            new Credential("/my-credential"));

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue("credential-password".getBytes(UTF_8));
    encryptedValueA.setNonce(new byte[]{});

    final UserCredentialVersionData credentialDataA =
            new UserCredentialVersionData("test-user");
    credentialDataA.setCredential(credentialName);
    credentialDataA.setEncryptedValueData(encryptedValueA);
    credentialDataA.setSalt("salt");
    subject.save(credentialDataA);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("another password".getBytes(UTF_8));
    encryptedValueB.setNonce(new byte[]{});

    final UserCredentialVersionData credentialDataB = new UserCredentialVersionData(
            "/my-credential");
    credentialDataB.setCredential(credentialName);
    credentialDataB.setEncryptedValueData(encryptedValueB);
    credentialDataB.setSalt("salt");
    subject.save(credentialDataB);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");
    assertThat(subject.findAllByName("/my-credential"), empty());
    assertEquals("Associated encryptedValues are deleted when user credential is deleted",
            nEncryptedValuesPre, encryptedValueRepository.count());
  }

  @Test
  public void delete_givenANonExistentCredentialName_returnsFalse() {
    assertThat(subject.delete("/does/not/exist"), equalTo(false));
  }

  @Test
  public void findMostRecent_givenACredentialNameWithoutVersions_returnsNull() {
    credentialDataService.save(new Credential("/my-unused-CREDENTIAL"));

    assertNull(subject.findMostRecent("/my-unused-CREDENTIAL"));
  }

  @Test
  public void findMostRecent_givenACredentialName_returnsMostRecentCredentialWithoutCaseSensitivity() {
    setupTestFixtureForFindMostRecent();

    final PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) subject.findMostRecent("/my-credential");

    assertThat(passwordCredential.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(passwordCredential2.getEncryptedValueData().getEncryptedValue(), equalTo("/my-new-password".getBytes(UTF_8)));
  }

  @Test
  public void findByUuid_givenAUuid_findsTheCredential() {

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValue.setEncryptedValue("credential-password".getBytes(UTF_8));
    encryptedValue.setNonce("nonce".getBytes(UTF_8));

    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential");
    passwordCredentialData.setEncryptedValueData(encryptedValue);
    final PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);
    final PasswordCredentialVersion savedCredential = (PasswordCredentialVersion) subject.save(credential);

    assertNotNull(savedCredential.getUuid());
    final PasswordCredentialVersion oneByUuid = (PasswordCredentialVersion) subject
            .findByUuid(savedCredential.getUuid().toString());
    assertThat(oneByUuid.getName(), equalTo("/my-credential"));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(),
            equalTo("credential-password".getBytes(UTF_8)));
  }

  @Test
  public void findByUuid_givenAUuid_thatDoesNotExist() {
    assertThatThrownBy(() -> {
      subject.findByUuid("some-uuid");
    }).hasMessage(ErrorMessages.RESOURCE_NOT_FOUND);
  }

  @Test
  public void findContainingName_givenACredentialName_returnsCredentialsInReverseChronologicalOrder() {
    final String valueName = "/value.Credential";
    final String passwordName = "/password/Credential";
    final String certificateName = "/certif/ic/atecredential";

    setupTestFixturesForFindContainingName(valueName, passwordName, certificateName);

    assertThat(subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
      hasProperty("name", equalTo(certificateName)),
      hasProperty("name", equalTo(valueName)),
      hasProperty("name", equalTo(passwordName))));

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValue.setEncryptedValue("new-encrypted-value".getBytes(UTF_8));
    encryptedValue.setNonce("nonce".getBytes(UTF_8));

    final ValueCredentialVersion valueCredential = (ValueCredentialVersion) subject.findMostRecent("/value.Credential");
    valueCredentialData.setEncryptedValueData(encryptedValue);
    subject.save(valueCredential);

    assertThat("The credentials are ordered by versionCreatedAt",
      subject.findContainingName("CREDENTIAL"), IsIterableContainingInOrder.contains(
        hasProperty("name", equalTo(certificateName)),
        hasProperty("name", equalTo(valueName)),
        hasProperty("name", equalTo(passwordName))
      ));
  }

  @Test
  public void findContainingName_givenACredentialName_returnsNonTransitionalVersion() {
    final CertificateCredentialVersion nonTransitionalVersion  = saveCertificate(2000000000123L, "/some-certificate");
    saveTransitionalCertificate(3000000000123L, "/some-certificate");

    final List<FindCredentialResult> credentialVersions = subject.findContainingName("/some-certificate");

    assertThat(credentialVersions.size(), equalTo(1));
    assertThat(credentialVersions.get(0).getVersionCreatedAt(), equalTo(nonTransitionalVersion.getVersionCreatedAt()));
  }

  @Test
  public void findContainingName_whenThereAreMultipleVerionsOfACredential() {
    savePassword(2000000000123L, "/foo/DUPLICATE");
    savePassword(1000000000123L, "/foo/DUPLICATE");
    savePassword(3000000000123L, "/bar/duplicate");
    savePassword(4000000000123L, "/bar/duplicate");

    final List<FindCredentialResult> credentials = subject.findContainingName("DUP");
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

    final PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) subject
      .findMostRecent("/credential/1");
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

    final List<FindCredentialResult> credentials = subject.findStartingWithPath("/dupsecret/");
    assertThat("should not return duplicate credential names",
      credentials.size(), equalTo(1));

    final FindCredentialResult credential = credentials.get(0);
    assertThat("should return the most recent credential",
      credential.getVersionCreatedAt(), equalTo(Instant.ofEpochMilli(3000000000123L)));
  }

  @Test
  public void findStartingWithPath_givenAPath_matchesFromTheStart() {
    setupTestFixtureForFindStartingWithPath();

    final List<FindCredentialResult> credentials = subject.findStartingWithPath("Credential");

    assertThat(credentials.size(), equalTo(3));
    assertThat(credentials, not(contains(hasProperty("name", equalTo("/not/So/Credential")))));

    assertThat("appends trailing slash to path", credentials,
      not(contains(hasProperty("name", equalTo("/CREDENTIALnotrailingslash")))));

    assertThat("appends trailing slash to path", credentials.get(0).getName().toLowerCase(),
      containsString("/credential/"));
  }

  @Test
  public void findAllPaths_returnsCompleteDirectoryStructure() {
    final String valueOther = "/fubario";
    final String valueName = "/value/Credential";
    final String passwordName = "/password/Credential";
    final String certificateName = "/certif/ic/ateCredential";

    ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(valueOther);
    ValueCredentialVersion valueCredential = new ValueCredentialVersion(valueCredentialData);
    subject.save(valueCredential);

    valueCredentialData = new ValueCredentialVersionData(valueName);
    valueCredential = new ValueCredentialVersion(valueCredentialData);
    subject.save(valueCredential);

    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    final PasswordCredentialVersion passwordCredential = new PasswordCredentialVersion(passwordCredentialData);
    subject.save(passwordCredential);

    final CertificateCredentialVersionData certificateCredentialData =
      new CertificateCredentialVersionData(certificateName);
    final CertificateCredentialVersion certificateCredential = new CertificateCredentialVersion(
      certificateCredentialData);
    subject.save(certificateCredential);

  }

  @Test
  public void findAllByName_whenProvidedAName_findsAllMatchingCredentials() {
    final PasswordCredentialVersion credential1 = savePassword(2000000000123L, "/secret1");
    final PasswordCredentialVersion credential2 = savePassword(4000000000123L, "/seCret1");
    savePassword(3000000000123L, "/Secret2");

    final List<CredentialVersion> credentialVersions = subject.findAllByName("/Secret1");
    assertThat(credentialVersions, containsInAnyOrder(hasProperty("uuid", equalTo(credential1.getUuid())),
      hasProperty("uuid", equalTo(credential2.getUuid()))));

    assertThat("returns empty list when no credential matches",
      subject.findAllByName("does/NOT/exist"), empty());
  }

  @Test
  public void findNByName_whenProvidedANameAndCount_findsCountMatchingCredentials() {
    final PasswordCredentialVersion credential1 = savePassword(2000000000125L, "/secret1");
    final PasswordCredentialVersion credential2 = savePassword(2000000000124L, "/seCret1");
    savePassword(2000000000123L, "/secret1");
    savePassword(3000000000123L, "/Secret2");

    final List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", 2);
    assertThat(
      credentialVersions,
      containsInAnyOrder(
        hasProperty("uuid", equalTo(credential1.getUuid())),
        hasProperty("uuid", equalTo(credential2.getUuid()))
      )
    );

    assertThat("returns empty list when no credential matches",
      subject.findNByName("does/NOT/exist", 12), empty());
  }

  @Test
  public void findNByName_whenAskedForTooManyVersions_returnsAllVersions() {
    final PasswordCredentialVersion credential1 = savePassword(2000000000123L, "/secret1");

    final List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", 2);

    assertThat(credentialVersions.size(), equalTo(1));
    assertThat(credentialVersions.get(0).getUuid(), equalTo(credential1.getUuid()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void findNByName_whenAskedForANegativeNumberOfVersions_throws() {
    savePassword(2000000000123L, "/secret1");

    final List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", -2);

    assertThat(credentialVersions.size(), equalTo(0));
  }

  @Test
  public void findCredential_withMetadata_returnsMetadata() {
    String name = "/metadata/test/password/with/metadata";
    fakeTimeSetter.accept(2000000000123L);
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      credential = credentialDataService.save(new Credential(name));
    }

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValue.setEncryptedValue(new byte[]{});
    encryptedValue.setNonce(new byte[]{});

    JsonNode metadata = null;
    try {
      metadata = objectMapper.readTree("{\"name\":\"test\"}");
    } catch (IOException e) {
      e.printStackTrace();
    }

    final PasswordCredentialVersionData credentialObject = new PasswordCredentialVersionData(name);
    credentialObject.setMetadata(metadata);
    credentialObject.setCredential(credential);
    credentialObject.setEncryptedValueData(encryptedValue);
    subject.save(credentialObject);

    CredentialVersion actual = subject.findAllByName(name).get(0);
    assertThat(actual.getMetadata(), equalTo(metadata));
  }

  @Test
  public void findCredential_withNoMetadata_returnsNullMetadata() throws Exception {
    String name = "/metadata/test/password/with/metadata";
    savePassword(2000000000123L, name);

    CredentialVersion actual = subject.findAllByName(name).get(0);
    assertThat(actual.getMetadata(), equalTo(null));
  }

  @Test
  public void findActiveByName_whenAskedForCertificate_returnsTransitionalValueInAddition() throws Exception {
    saveCertificate(2000000000123L, "/some-certificate");
    final CertificateCredentialVersion version2 = saveTransitionalCertificate(2000000000123L, "/some-certificate");
    final CertificateCredentialVersion version3 = saveCertificate(2000000000229L, "/some-certificate");

    final List<CredentialVersion> credentialVersions = subject.findActiveByName("/some-certificate");

    assertThat(credentialVersions.size(), equalTo(2));
    assertThat(credentialVersions,
      containsInAnyOrder(
        hasProperty("uuid", equalTo(version2.getUuid())),
        hasProperty("uuid", equalTo(version3.getUuid()))
      ));
  }

  @Test
  public void findActiveByName_whenAskedNonCertificateType_returnsOneCredentialValue() throws Exception {
    savePassword(2000000000123L, "/test/password");
    savePassword(3000000000123L, "/test/password");
    final PasswordCredentialVersion password3 = savePassword(4000000000123L, "/test/password");

    final List<CredentialVersion> credentialVersions = subject.findActiveByName("/test/password");

    assertThat(credentialVersions.size(), equalTo(1));
    assertThat(credentialVersions, contains(
      hasProperty("uuid", equalTo(password3.getUuid()))));
  }

  @Test
  public void findAllCertificateCredentialsByCaName_returnsCertificatesSignedByTheCa() {
    saveCertificate(2000000000123L, "/ca-cert");
    saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    saveCertificate(2000000000124L, "/ca-cert2");
    saveCertificateByCa(2000000000127L, "/cert3", "/ca-cert2");

    List<String> certificates = subject.findAllCertificateCredentialsByCaName("/ca-cert");
    assertThat(certificates, containsInAnyOrder(equalTo("/cert1"),
      equalTo("/cert2")));
    assertThat(certificates, not(hasItem("/cert3")));
    certificates = subject.findAllCertificateCredentialsByCaName("/ca-cert2");
    assertThat(certificates, hasItem("/cert3"));
    assertThat(certificates, not(hasItem("/cert1")));
    assertThat(certificates, not(hasItem("/cert2")));
  }

  @Test
  public void findAllCertificateCredentialsByCaName_isCaseInsensitive() {
    saveCertificate(2000000000123L, "/ca-cert");
    saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    final List<String> certificates = subject.findAllCertificateCredentialsByCaName("/ca-CERT");
    assertThat(certificates, containsInAnyOrder(equalTo("/cert1"),
      equalTo("/cert2")));
  }

  private PasswordCredentialVersion savePassword(final long timeMillis, final String name, final UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      credential = credentialDataService.save(new Credential(name));
    }

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(canaryUuid);
    encryptedValue.setEncryptedValue(new byte[]{});
    encryptedValue.setNonce(new byte[]{});

    final PasswordCredentialVersionData credentialObject = new PasswordCredentialVersionData("test-password");
    credentialObject.setCredential(credential);
    credentialObject.setEncryptedValueData(encryptedValue);
    return (PasswordCredentialVersion) subject.save(credentialObject);
  }

  private PasswordCredentialVersion savePassword(final long timeMillis, final String credentialName) {
    return savePassword(timeMillis, credentialName, activeCanaryUuid);
  }

  private CertificateCredentialVersion saveCertificate(final long timeMillis, final String name, final String caName, final UUID canaryUuid,
                                                       final boolean transitional) {
    fakeTimeSetter.accept(timeMillis);
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      credential = credentialDataService.save(new Credential(name));
    }

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(canaryUuid);
    encryptedValue.setEncryptedValue(new byte[]{});
    encryptedValue.setNonce(new byte[]{});

    final CertificateCredentialVersionData credentialObject = new CertificateCredentialVersionData("test");
    credentialObject.setCredential(credential);
    credentialObject.setEncryptedValueData(encryptedValue);
    if (caName != null) {
      credentialObject.setCaName(caName);
    }
    credentialObject.setTransitional(transitional);
    return (CertificateCredentialVersion) subject.save(credentialObject);
  }

  private CertificateCredentialVersion saveCertificate(final long timeMillis, final String credentialName) {
    return saveCertificate(timeMillis, credentialName, null, activeCanaryUuid, false);
  }

  private CertificateCredentialVersion saveTransitionalCertificate(final long timeMillis, final String credentialName) {
    return saveCertificate(timeMillis, credentialName, null, activeCanaryUuid, true);
  }

  private CertificateCredentialVersion saveCertificateByCa(
    final long timeMillis, final String credentialName, final String caName) {
    return saveCertificate(timeMillis, credentialName, caName, activeCanaryUuid, false);
  }


  private void setupTestFixtureForFindMostRecent() {
    final Credential credential = credentialDataService
      .save(new Credential("/my-CREDENTIAL"));

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue("/my-old-password".getBytes(UTF_8));
    encryptedValueA.setNonce(new byte[]{});

    namedPasswordCredential1 = new PasswordCredentialVersionData("test-password");
    namedPasswordCredential1.setCredential(credential);
    namedPasswordCredential1.setEncryptedValueData(encryptedValueA);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("/my-new-password".getBytes(UTF_8));
    encryptedValueB.setNonce(new byte[]{});

    passwordCredential2 = new PasswordCredentialVersionData("test-password");
    passwordCredential2.setCredential(credential);
    passwordCredential2.setEncryptedValueData(encryptedValueB);

    subject.save(namedPasswordCredential1);
    fakeTimeSetter.accept(345346L); // 1 second later
    subject.save(passwordCredential2);
  }

  private void setupTestFixturesForFindContainingName(
    final String valueName,
    final String passwordName,
    final String certificateName
  ) {

    final EncryptedValue encryptedValueA = new EncryptedValue();
    encryptedValueA.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueA.setEncryptedValue("value".getBytes(UTF_8));
    encryptedValueA.setNonce(new byte[]{});

    fakeTimeSetter.accept(2000000000123L);
    valueCredentialData = new ValueCredentialVersionData(valueName);
    valueCredentialData.setEncryptedValueData(encryptedValueA);
    final ValueCredentialVersion namedValueCredential = new ValueCredentialVersion(valueCredentialData);
    namedValueCredential.setEncryptor(encryptor);
    subject.save(namedValueCredential);

    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/mySe.cret");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(activeCanaryUuid, "", ""));
    new PasswordCredentialVersion(passwordCredentialData);
    final PasswordCredentialVersion namedPasswordCredential;
    subject.save(namedValueCredential);

    final EncryptedValue encryptedValueB = new EncryptedValue();
    encryptedValueB.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValueB.setEncryptedValue("password".getBytes(UTF_8));
    encryptedValueB.setNonce(new byte[]{});

    fakeTimeSetter.accept(1000000000123L);
    passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    passwordCredentialData.setEncryptedValueData(encryptedValueB);
    namedPasswordCredential = new PasswordCredentialVersion(passwordCredentialData);
    subject.save(namedPasswordCredential);

    CertificateCredentialVersionData certificateCredentialData = new CertificateCredentialVersionData(
      "/myseecret");
    CertificateCredentialVersion certificateCredential = new CertificateCredentialVersion(
      certificateCredentialData);
    subject.save(certificateCredential);

    fakeTimeSetter.accept(3000000000123L);
    certificateCredentialData = new CertificateCredentialVersionData(
      certificateName);
    certificateCredential = new CertificateCredentialVersion(certificateCredentialData);
    subject.save(certificateCredential);
  }

  @Test
  public void shouldThrowAnMaximumSizeException_whenDataExceedsMaximumSize() {
    if (System.getProperty(activeProfilesString).contains(unitTestPostgresProfile)) {
      return;
    }

    final String credentialName = "some_name";
    final ValueCredentialVersionData entity = new ValueCredentialVersionData("test-credential");
    final Credential credential = credentialRepository.save(new Credential(credentialName));

    EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptedValue(DatabaseUtilities.Companion.getExceedsMaxBlobStoreSizeBytes());
    encryptedValue.setEncryptionKeyUuid(activeCanaryUuid);
    encryptedValue.setNonce("nonce".getBytes(UTF_8));

    entity.setCredential(credential);
    entity.setEncryptedValueData(encryptedValue);

    assertThatThrownBy(() -> {
      subject.save(entity);
    }).isInstanceOf(MaximumSizeException.class);
  }

  private void setupTestFixtureForFindStartingWithPath() {
    savePassword(2000000000123L, "/credential/1");
    savePassword(3000000000123L, "/Credential/2");
    savePassword(1000000000123L, "/CREDENTIAL/3");
    savePassword(1000000000123L, "/not/So/Credential");
    savePassword(1000000000123L, "/CREDENTIALnotrailingslash");
  }
}
