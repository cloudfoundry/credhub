package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.domain.ValueCredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.helper.EncryptionCanaryHelper;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.cloudfoundry.credhub.view.FindCredentialResult;
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
import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@Transactional
public class CredentialVersionDataServiceTest {

  @Autowired
  CredentialVersionRepository credentialVersionRepository;


  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  CredentialDataService credentialDataService;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  CredentialVersionDataService subject;

  @Autowired
  Encryptor encryptor;

  private Consumer<Long> fakeTimeSetter;
  private UUID activeCanaryUuid;
  private UUID unknownCanaryUuid;
  private PasswordCredentialVersionData passwordCredential2;
  private PasswordCredentialVersionData namedPasswordCredential1;
  private ValueCredentialVersionData valueCredentialData;

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
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(
        activeCanaryUuid,
        "credential-password",
        ""
    ));
    PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);
    credential.setEncryptor(encryptor);
    CredentialVersion savedCredentialVersion = subject.save(credential);

    assertNotNull(savedCredentialVersion);

    PasswordCredentialVersion savedPasswordCredential = (PasswordCredentialVersion) subject
        .findMostRecent("/my-credential");
    CredentialVersionData credentialVersionData = credentialVersionRepository.findOneByUuid(savedCredentialVersion.getUuid());

    assertThat(savedPasswordCredential.getName(), equalTo(credential.getName()));
    assertThat(savedPasswordCredential.getUuid(), equalTo(credential.getUuid()));

    assertThat(credentialVersionData.getCredential().getName(), equalTo("/my-credential"));
    assertThat(credentialVersionData.getEncryptedValueData().getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void save_givenAnExistingCredential_updatesTheCredential() {
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential-2");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(
        activeCanaryUuid,
        "credential-password",
        "nonce"
    ));
    PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credential);

    passwordCredentialData.getEncryptedValueData().setEncryptedValue("irynas-ninja-skills".getBytes());

    subject.save(credential);

    PasswordCredentialVersion savedPasswordCredential = (PasswordCredentialVersion) subject
        .findMostRecent("/my-credential-2");
    CredentialVersionData credentialVersionData = credentialVersionRepository
        .findOneByUuid(savedPasswordCredential.getUuid());

    assertThat(credentialVersionData.getCredential().getName(), equalTo("/my-credential-2"));
    assertThat(credentialVersionData.getEncryptedValueData().getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));
    assertThat(credentialVersionData.getUuid(), equalTo(credential.getUuid()));
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_givenAnExistingCredential_throwsExceptionIfTypeMismatch() {
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential-3");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue()
        .setEncryptionKeyUuid(activeCanaryUuid)
        .setEncryptedValue(new byte[]{})
        .setNonce(new byte[]{}));
    PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credential);

    ValueCredentialVersionData newCredentialData = new ValueCredentialVersionData();
    newCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("some value".getBytes()));
    newCredentialData.setCredential(passwordCredentialData.getCredential());
    ValueCredentialVersion newCredential = new ValueCredentialVersion(newCredentialData);

    subject.save(newCredential);

  }

  @Test
  public void save_givenANewCredential_generatesTheUuid() {
    SshCredentialVersion credential = new SshCredentialVersion("/my-credential-2")
        .setEncryptor(encryptor)
        .setPrivateKey("privatekey")
        .setPublicKey("fake-public-key");
    SshCredentialVersion savedCredential = subject.save(credential);

    UUID generatedUuid = savedCredential.getUuid();
    assertNotNull(generatedUuid);

    savedCredential.setPublicKey("updated-fake-public-key");
    savedCredential = subject.save(savedCredential);

    assertThat(savedCredential.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenACredentialWithALeadingSlash_savesWithTheLeadingSlash() {
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my/credential");
    PasswordCredentialVersion credentialWithLeadingSlash = new PasswordCredentialVersion(passwordCredentialData);

    subject.save(credentialWithLeadingSlash);

    CredentialVersion savedCredentialVersion = subject.findMostRecent("/my/credential");
    assertThat(savedCredentialVersion.getCredential().getName(), equalTo("/my/credential"));
  }

  @Test
  public void save_whenTheCredentialSavedWithEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("/my-credential");
    SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData).setEncryptor(encryptor).setPrivateKey("private-key").setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void save_whenTheCredentialSavedWithoutEncryptedValueSet_doesNotSetTheMasterEncryptionKeyUuid() {
    SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("/my-credential");
    SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData).setEncryptor(encryptor).setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), nullValue());
  }

  @Test
  public void delete_onAnExistingCredential_returnsTrue() {
    credentialDataService.save(new Credential("/my-credential"));

    assertThat(subject.delete("/my-credential"), equalTo(true));
  }

  @Test
  public void delete_onACredentialName_deletesAllCredentialsWithTheName() {
    Credential credential = credentialDataService
        .save(new Credential("/my-credential"));

    PasswordCredentialVersionData credentialData = new PasswordCredentialVersionData();
    credentialData.setCredential(credential);
    credentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("credential-password".getBytes())
      .setNonce("nonce".getBytes()));
    subject.save(credentialData);

    credentialData = new PasswordCredentialVersionData("/my-credential");
    credentialData.setCredential(credential);
    credentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("another password".getBytes())
      .setNonce("nonce".getBytes()));
    subject.save(credentialData);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");

    assertThat(subject.findAllByName("/my-credential"), hasSize(0));
    assertNull(credentialDataService.find("/my-credential"));
  }

  @Test
  public void delete_givenACredentialNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
    Credential credentialName = credentialDataService
        .save(new Credential("/my-credential"));

    PasswordCredentialVersionData credential = new PasswordCredentialVersionData();
    credential.setCredential(credentialName);
    credential.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("credential-password".getBytes())
      .setNonce(new byte[]{}));
    subject.save(credential);

    credential = new PasswordCredentialVersionData();
    credential.setCredential(credentialName);
    credential.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("another password".getBytes())
      .setNonce(new byte[]{}));

    subject.save(credential);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/MY-CREDENTIAL");

    assertThat(subject.findAllByName("/my-credential"), empty());
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

    PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) subject.findMostRecent("/my-credential");

    assertThat(passwordCredential.getName(), equalTo("/my-CREDENTIAL"));
    assertThat(passwordCredential2.getEncryptedValueData().getEncryptedValue(), equalTo("/my-new-password".getBytes()));
  }

  @Test
  public void findByUuid_givenAUuid_findsTheCredential() {
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/my-credential");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("credential-password".getBytes())
      .setNonce("nonce".getBytes()));
    PasswordCredentialVersion credential = new PasswordCredentialVersion(passwordCredentialData);
    PasswordCredentialVersion savedCredential = subject.save(credential);

    assertNotNull(savedCredential.getUuid());
    PasswordCredentialVersion oneByUuid = (PasswordCredentialVersion) subject
        .findByUuid(savedCredential.getUuid().toString());
    assertThat(oneByUuid.getName(), equalTo("/my-credential"));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(),
        equalTo("credential-password".getBytes()));
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

    ValueCredentialVersion valueCredential = (ValueCredentialVersion) subject.findMostRecent("/value.Credential");
    valueCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("new-encrypted-value".getBytes())
      .setNonce("nonce".getBytes()));
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
    savePassword(2000000000123L, "/foo/DUPLICATE");
    savePassword(1000000000123L, "/foo/DUPLICATE");
    savePassword(3000000000123L, "/bar/duplicate");
    savePassword(4000000000123L, "/bar/duplicate");

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

    PasswordCredentialVersion passwordCredential = (PasswordCredentialVersion) subject
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

    ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData(valueOther);
    ValueCredentialVersion valueCredential = new ValueCredentialVersion(valueCredentialData);
    subject.save(valueCredential);

    valueCredentialData = new ValueCredentialVersionData(valueName);
    valueCredential = new ValueCredentialVersion(valueCredentialData);
    subject.save(valueCredential);

    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    PasswordCredentialVersion passwordCredential = new PasswordCredentialVersion(passwordCredentialData);
    subject.save(passwordCredential);

    CertificateCredentialVersionData certificateCredentialData =
        new CertificateCredentialVersionData(certificateName);
    CertificateCredentialVersion certificateCredential = new CertificateCredentialVersion(
        certificateCredentialData);
    subject.save(certificateCredential);

    assertThat(subject.findAllPaths(),
        equalTo(newArrayList("/", "/certif/", "/certif/ic/", "/password/", "/value/")));
  }

  @Test
  public void findAllByName_whenProvidedAName_findsAllMatchingCredentials() {
    PasswordCredentialVersion credential1 = savePassword(2000000000123L, "/secret1");
    PasswordCredentialVersion credential2 = savePassword(4000000000123L, "/seCret1");
    savePassword(3000000000123L, "/Secret2");

    List<CredentialVersion> credentialVersions = subject.findAllByName("/Secret1");
    assertThat(credentialVersions, containsInAnyOrder(hasProperty("uuid", equalTo(credential1.getUuid())),
        hasProperty("uuid", equalTo(credential2.getUuid()))));

    assertThat("returns empty list when no credential matches",
        subject.findAllByName("does/NOT/exist"), empty());
  }

  @Test
  public void findNByName_whenProvidedANameAndCount_findsCountMatchingCredentials() {
    PasswordCredentialVersion credential1 = savePassword(2000000000125L, "/secret1");
    PasswordCredentialVersion credential2 = savePassword(2000000000124L, "/seCret1");
    PasswordCredentialVersion credential3 = savePassword(2000000000123L, "/secret1");
    savePassword(3000000000123L, "/Secret2");

    List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", 2);
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
    PasswordCredentialVersion credential1 = savePassword(2000000000123L, "/secret1");

    List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", 2);

    assertThat(credentialVersions.size(), equalTo(1));
    assertThat(credentialVersions.get(0).getUuid(), equalTo(credential1.getUuid()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void findNByName_whenAskedForANegativeNumberOfVersions_throws() {
    PasswordCredentialVersion credential1 = savePassword(2000000000123L, "/secret1");

    List<CredentialVersion> credentialVersions = subject.findNByName("/Secret1", -2);

    assertThat(credentialVersions.size(), equalTo(0));
  }

  @Test
  public void findEncryptedWithAvailableInactiveKeys() {
    UUID oldCanaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService)
        .getUuid();

    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(Arrays.asList(oldCanaryUuid));

    PasswordCredentialVersion credential1 = savePassword(2000000000123L, "credential", oldCanaryUuid);
    PasswordCredentialVersion credential2 = savePassword(3000000000123L, "ANOTHER", oldCanaryUuid);
    PasswordCredentialVersion credential3 = savePassword(4000000000123L, "password", oldCanaryUuid);
    PasswordCredentialVersion credential1Newer = savePassword(5000000000123L, "credential", oldCanaryUuid);

    PasswordCredentialVersion credentialEncryptedWithActiveKey = savePassword(3000000000123L,
        "ANOTHER", activeCanaryUuid);
    PasswordCredentialVersion newerCredentialEncryptedWithActiveKey = savePassword(
        4000000000123L, "ANOTHER", activeCanaryUuid);
    PasswordCredentialVersion credentialEncryptedWithUnknownKey = savePassword(4000000000123L,
        "ANOTHER", unknownCanaryUuid);

    final Slice<CredentialVersion> credentials = subject.findEncryptedWithAvailableInactiveKey();
    List<UUID> credentialUuids = credentials.getContent().stream()
        .map(credential -> credential.getUuid())
        .collect(Collectors.toList());

    assertThat(credentialUuids, not(contains(credentialEncryptedWithActiveKey.getUuid())));
    assertThat(credentialUuids, not(contains(newerCredentialEncryptedWithActiveKey.getUuid())));

    assertThat(credentialUuids, not(contains(credentialEncryptedWithUnknownKey.getUuid())));

    assertThat(credentialUuids,
        containsInAnyOrder(credential1.getUuid(), credential2.getUuid(), credential3.getUuid(),
            credential1Newer.getUuid()));
  }

  @Test
  public void findAllCertificateCredentialsByCaName_returnsCertificatesSignedByTheCa() {
    CertificateCredentialVersion caCert = saveCertificate(2000000000123L, "/ca-cert");
    CertificateCredentialVersion cert1 = saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    CertificateCredentialVersion cert2 = saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    CertificateCredentialVersion caCert2 = saveCertificate(2000000000124L, "/ca-cert2");
    CertificateCredentialVersion cert3 = saveCertificateByCa(2000000000127L, "/cert3", "/ca-cert2");

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
    CertificateCredentialVersion caCert = saveCertificate(2000000000123L, "/ca-cert");
    CertificateCredentialVersion cert1 = saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    CertificateCredentialVersion cert2 = saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    List<String> certificates = subject.findAllCertificateCredentialsByCaName("/ca-CERT");
    assertThat(certificates, containsInAnyOrder(equalTo("/cert1"),
        equalTo("/cert2")));

  }

  private PasswordCredentialVersion savePassword(long timeMillis, String name, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      credential = credentialDataService.save(new Credential(name));
    }
    PasswordCredentialVersionData credentialObject = new PasswordCredentialVersionData();
    credentialObject.setCredential(credential);
    credentialObject.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(canaryUuid)
      .setEncryptedValue(new byte[]{})
      .setNonce(new byte[]{}));
    return subject.save(credentialObject);
  }

  private PasswordCredentialVersion savePassword(long timeMillis, String credentialName) {
    return savePassword(timeMillis, credentialName, activeCanaryUuid);
  }

  private CertificateCredentialVersion saveCertificate(long timeMillis, String name, String caName, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      credential = credentialDataService.save(new Credential(name));
    }
    CertificateCredentialVersionData credentialObject = new CertificateCredentialVersionData();
    credentialObject.setCredential(credential);
    credentialObject.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(canaryUuid)
      .setEncryptedValue(new byte[]{})
      .setNonce(new byte[]{}));
    if (caName != null){
      credentialObject.setCaName(caName);
    }
    return subject.save(credentialObject);
  }

  private CertificateCredentialVersion saveCertificate(long timeMillis, String credentialName) {
    return saveCertificate(timeMillis, credentialName, null, activeCanaryUuid);
  }

  private CertificateCredentialVersion saveCertificateByCa(long timeMillis, String credentialName, String caName) {
    return saveCertificate(timeMillis, credentialName, caName, activeCanaryUuid);
  }


  private void setupTestFixtureForFindMostRecent() {
    Credential credential = credentialDataService
        .save(new Credential("/my-CREDENTIAL"));

    namedPasswordCredential1 = new PasswordCredentialVersionData();
    namedPasswordCredential1.setCredential(credential);
    namedPasswordCredential1.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("/my-old-password".getBytes())
      .setNonce(new byte[]{}));

    passwordCredential2 = new PasswordCredentialVersionData();
    passwordCredential2.setCredential(credential);
    passwordCredential2.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("/my-new-password".getBytes())
      .setNonce(new byte[]{}));

    subject.save(namedPasswordCredential1);
    fakeTimeSetter.accept(345346L); // 1 second later
    subject.save(passwordCredential2);

  }

  private void setupTestFixturesForFindContainingName(String valueName,
      String passwordName,
      String certificateName) {

    fakeTimeSetter.accept(2000000000123L);
    valueCredentialData = new ValueCredentialVersionData(valueName);
    valueCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("value".getBytes())
      .setNonce(new byte[]{}));
    ValueCredentialVersion namedValueCredential = new ValueCredentialVersion(valueCredentialData);
    namedValueCredential.setEncryptor(encryptor);
    subject.save(namedValueCredential);

    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("/mySe.cret");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue(activeCanaryUuid, "", ""));
    new PasswordCredentialVersion(passwordCredentialData);
    PasswordCredentialVersion namedPasswordCredential;
    subject.save(namedValueCredential);

    fakeTimeSetter.accept(1000000000123L);
    passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    passwordCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(activeCanaryUuid)
      .setEncryptedValue("password".getBytes())
      .setNonce(new byte[]{}));
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

  private void setupTestFixtureForFindStartingWithPath() {
    savePassword(2000000000123L, "/credential/1");
    savePassword(3000000000123L, "/Credential/2");
    savePassword(1000000000123L, "/CREDENTIAL/3");
    savePassword(1000000000123L, "/not/So/Credential");
    savePassword(1000000000123L, "/CREDENTIALnotrailingslash");
  }
}
