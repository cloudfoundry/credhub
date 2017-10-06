package io.pivotal.security.data;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.entity.CertificateCredentialVersion;
import io.pivotal.security.entity.CredentialVersion;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.PasswordCredentialVersion;
import io.pivotal.security.entity.SshCredentialVersion;
import io.pivotal.security.entity.ValueCredentialVersion;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.repository.CredentialVersionRepository;
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
public class CredentialVersionServiceTest {

  @Autowired
  CredentialVersionRepository credentialVersionRepository;


  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  CredentialNameDataService credentialNameDataService;

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
  private PasswordCredentialVersion passwordCredential2;
  private PasswordCredentialVersion namedPasswordCredential1;
  private ValueCredentialVersion valueCredentialData;

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
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my-credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    passwordCredentialData.setNonce(new byte[]{});
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);
    credential.setEncryptor(encryptor);
    Credential savedCredential = subject.save(credential);

    assertNotNull(savedCredential);

    PasswordCredential savedPasswordCredential = (PasswordCredential) subject
        .findMostRecent("/my-credential");
    CredentialVersion credentialVersion = credentialVersionRepository.findOneByUuid(savedCredential.getUuid());

    assertThat(savedPasswordCredential.getName(), equalTo(credential.getName()));
    assertThat(savedPasswordCredential.getUuid(), equalTo(credential.getUuid()));

    assertThat(credentialVersion.getCredentialName().getName(), equalTo("/my-credential"));
    assertThat(credentialVersion.getEncryptedValue(), equalTo("credential-password".getBytes()));
  }

  @Test
  public void save_givenAnExistingCredential_updatesTheCredential() {
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my-credential-2");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    passwordCredentialData.setNonce("nonce".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);

    subject.save(credential);

    passwordCredentialData.setEncryptedValue("irynas-ninja-skills".getBytes());

    subject.save(credential);

    PasswordCredential savedPasswordCredential = (PasswordCredential) subject
        .findMostRecent("/my-credential-2");
    CredentialVersion credentialVersion = credentialVersionRepository
        .findOneByUuid(savedPasswordCredential.getUuid());

    assertThat(credentialVersion.getCredentialName().getName(), equalTo("/my-credential-2"));
    assertThat(credentialVersion.getEncryptedValue(), equalTo("irynas-ninja-skills".getBytes()));
    assertThat(credentialVersion.getUuid(), equalTo(credential.getUuid()));
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_givenAnExistingCredential_throwsExceptionIfTypeMismatch() {
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my-credential-3");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    passwordCredentialData.setEncryptedValue(new byte[]{});
    passwordCredentialData.setNonce(new byte[]{});
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);

    subject.save(credential);

    //forcing credentialName uuid to match so we can test race conditions on type change
    ValueCredentialVersion newCredentialData = new ValueCredentialVersion();
    newCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    newCredentialData.setEncryptedValue("some value".getBytes());
    newCredentialData.setCredentialName(passwordCredentialData.getCredentialName());
    ValueCredential newCredential = new ValueCredential(newCredentialData);

    subject.save(newCredential);

  }

  @Test
  public void save_givenANewCredential_generatesTheUuid() {
    SshCredential credential = new SshCredential("/my-credential-2")
        .setEncryptor(encryptor)
        .setPrivateKey("privatekey")
        .setPublicKey("fake-public-key");
    SshCredential savedCredential = subject.save(credential);

    UUID generatedUuid = savedCredential.getUuid();
    assertNotNull(generatedUuid);

    savedCredential.setPublicKey("updated-fake-public-key");
    savedCredential = subject.save(savedCredential);

    assertThat(savedCredential.getUuid(), equalTo(generatedUuid));
  }

  @Test
  public void save_givenACredentialWithALeadingSlash_savesWithTheLeadingSlash() {
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my/credential");
    PasswordCredential credentialWithLeadingSlash = new PasswordCredential(passwordCredentialData);

    subject.save(credentialWithLeadingSlash);

    Credential savedCredential = subject.findMostRecent("/my/credential");
    assertThat(savedCredential.getCredentialName().getName(), equalTo("/my/credential"));
  }

  @Test
  public void save_whenTheCredentialSavedWithEncryptedValueSet_setsTheMasterEncryptionKeyUuid() {
    SshCredentialVersion sshCredentialData = new SshCredentialVersion("/my-credential");
    SshCredential credential = new SshCredential(sshCredentialData).setEncryptor(encryptor).setPrivateKey("private-key").setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), equalTo(activeCanaryUuid));
  }

  @Test
  public void save_whenTheCredentialSavedWithoutEncryptedValueSet_doesNotSetTheMasterEncryptionKeyUuid() {
    SshCredentialVersion sshCredentialData = new SshCredentialVersion("/my-credential");
    SshCredential credential = new SshCredential(sshCredentialData).setEncryptor(encryptor).setPublicKey("fake-public-key");
    subject.save(credential);

    assertThat(sshCredentialData.getEncryptionKeyUuid(), nullValue());
  }

  @Test
  public void delete_onAnExistingCredential_returnsTrue() {
    credentialNameDataService.save(new CredentialName("/my-credential"));

    assertThat(subject.delete("/my-credential"), equalTo(true));
  }

  @Test
  public void delete_onACredentialName_deletesAllCredentialsWithTheName() {
    CredentialName credentialName = credentialNameDataService
        .save(new CredentialName("/my-credential"));

    PasswordCredentialVersion credentialData = new PasswordCredentialVersion();
    credentialData.setCredentialName(credentialName);
    credentialData.setEncryptionKeyUuid(activeCanaryUuid);
    credentialData.setEncryptedValue("credential-password".getBytes());
    credentialData.setNonce("nonce".getBytes());
    subject.save(credentialData);

    credentialData = new PasswordCredentialVersion("/my-credential");
    credentialData.setCredentialName(credentialName);
    credentialData.setEncryptionKeyUuid(activeCanaryUuid);
    credentialData.setEncryptedValue("another password".getBytes());
    credentialData.setNonce("nonce".getBytes());
    subject.save(credentialData);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("/my-credential");

    assertThat(subject.findAllByName("/my-credential"), hasSize(0));
    assertNull(credentialNameDataService.find("/my-credential"));
  }

  @Test
  public void delete_givenACredentialNameCasedDifferentlyFromTheActual_shouldBeCaseInsensitive() {
    CredentialName credentialName = credentialNameDataService
        .save(new CredentialName("/my-credential"));

    PasswordCredentialVersion credential = new PasswordCredentialVersion();
    credential.setCredentialName(credentialName);
    credential.setEncryptionKeyUuid(activeCanaryUuid);
    credential.setEncryptedValue("credential-password".getBytes());
    credential.setNonce(new byte[]{});
    subject.save(credential);

    credential = new PasswordCredentialVersion();
    credential.setCredentialName(credentialName);
    credential.setEncryptionKeyUuid(activeCanaryUuid);
    credential.setEncryptedValue("another password".getBytes());
    credential.setNonce(new byte[]{});

    subject.save(credential);

    assertThat(subject.findAllByName("/my-credential"), hasSize(2));

    subject.delete("MY-CREDENTIAL");

    assertThat(subject.findAllByName("/my-credential"), empty());
  }

  @Test
  public void delete_givenACredentialNameWithoutALeadingSlash_deletesTheCredentialAnyway() {
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my/credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    passwordCredentialData.setNonce("nonce".getBytes());
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
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/my-credential");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("credential-password".getBytes());
    passwordCredentialData.setNonce("nonce".getBytes());
    PasswordCredential credential = new PasswordCredential(passwordCredentialData);
    PasswordCredential savedCredential = subject.save(credential);

    assertNotNull(savedCredential.getUuid());
    PasswordCredential oneByUuid = (PasswordCredential) subject
        .findByUuid(savedCredential.getUuid().toString());
    assertThat(oneByUuid.getName(), equalTo("/my-credential"));
    assertThat(passwordCredentialData.getEncryptedValue(),
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

    ValueCredential valueCredential = (ValueCredential) subject.findMostRecent("value.Credential");
    valueCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    valueCredentialData.setEncryptedValue("new-encrypted-value".getBytes());
    valueCredentialData.setNonce("nonce".getBytes());
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

    ValueCredentialVersion valueCredentialData = new ValueCredentialVersion(valueOther);
    ValueCredential valueCredential = new ValueCredential(valueCredentialData);
    subject.save(valueCredential);

    valueCredentialData = new ValueCredentialVersion(valueName);
    valueCredential = new ValueCredential(valueCredentialData);
    subject.save(valueCredential);

    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion(passwordName);
    PasswordCredential passwordCredential = new PasswordCredential(passwordCredentialData);
    subject.save(passwordCredential);

    CertificateCredentialVersion certificateCredentialData =
        new CertificateCredentialVersion(certificateName);
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
  public void findNByName_whenProvidedANameAndCount_findsCountMatchingCredentials() {
    PasswordCredential credential1 = savePassword(2000000000125L, "/secret1");
    PasswordCredential credential2 = savePassword(2000000000124L, "/seCret1");
    PasswordCredential credential3 = savePassword(2000000000123L, "/secret1");
    savePassword(3000000000123L, "/Secret2");

    List<Credential> credentials = subject.findNByName("/Secret1", 2);
    assertThat(
        credentials,
        containsInAnyOrder(
            hasProperty("uuid", equalTo(credential1.getUuid())),
            hasProperty("uuid", equalTo(credential2.getUuid()))
        )
    );

    credentials = subject.findNByName("Secret1", 3);
    assertThat("prepends slash to search if missing",
        credentials,
        containsInAnyOrder(
            hasProperty("uuid", equalTo(credential1.getUuid())),
            hasProperty("uuid", equalTo(credential2.getUuid())),
            hasProperty("uuid", equalTo(credential3.getUuid()))
        )
    );

    assertThat("returns empty list when no credential matches",
        subject.findNByName("does/NOT/exist", 12), empty());
  }

  @Test
  public void findNByName_whenAskedForTooManyVersions_returnsAllVersions() {
    PasswordCredential credential1 = savePassword(2000000000123L, "/secret1");

    List<Credential> credentials = subject.findNByName("/Secret1", 2);

    assertThat(credentials.size(), equalTo(1));
    assertThat(credentials.get(0).getUuid(), equalTo(credential1.getUuid()));
  }

  @Test(expected = IllegalArgumentException.class)
  public void findNByName_whenAskedForANegativeNumberOfVersions_throws() {
    PasswordCredential credential1 = savePassword(2000000000123L, "/secret1");

    List<Credential> credentials = subject.findNByName("/Secret1", -2);

    assertThat(credentials.size(), equalTo(0));
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
    CertificateCredential caCert = saveCertificate(2000000000123L, "/ca-cert");
    CertificateCredential cert1 = saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    CertificateCredential cert2 = saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    CertificateCredential caCert2 = saveCertificate(2000000000124L, "/ca-cert2");
    CertificateCredential cert3 = saveCertificateByCa(2000000000127L, "/cert3", "/ca-cert2");

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
    CertificateCredential caCert = saveCertificate(2000000000123L, "/ca-cert");
    CertificateCredential cert1 = saveCertificateByCa(2000000000125L, "/cert1", "/ca-cert");
    CertificateCredential cert2 = saveCertificateByCa(2000000000126L, "/cert2", "/ca-cert");

    List<String> certificates = subject.findAllCertificateCredentialsByCaName("/ca-CERT");
    assertThat(certificates, containsInAnyOrder(equalTo("/cert1"),
        equalTo("/cert2")));

  }

  private PasswordCredential savePassword(long timeMillis, String name, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName == null) {
      credentialName = credentialNameDataService.save(new CredentialName(name));
    }
    PasswordCredentialVersion credentialObject = new PasswordCredentialVersion();
    credentialObject.setCredentialName(credentialName);
    credentialObject.setEncryptionKeyUuid(canaryUuid);
    credentialObject.setEncryptedValue(new byte[]{});
    credentialObject.setNonce(new byte[]{});
    return subject.save(credentialObject);
  }

  private PasswordCredential savePassword(long timeMillis, String credentialName) {
    return savePassword(timeMillis, credentialName, activeCanaryUuid);
  }

  private CertificateCredential saveCertificate(long timeMillis, String name, String caName, UUID canaryUuid) {
    fakeTimeSetter.accept(timeMillis);
    CredentialName credentialName = credentialNameDataService.find(name);
    if (credentialName == null) {
      credentialName = credentialNameDataService.save(new CredentialName(name));
    }
    CertificateCredentialVersion credentialObject = new CertificateCredentialVersion();
    credentialObject.setCredentialName(credentialName);
    credentialObject.setEncryptionKeyUuid(canaryUuid);
    credentialObject.setEncryptedValue(new byte[]{});
    credentialObject.setNonce(new byte[]{});
    if (caName != null){
      credentialObject.setCaName(caName);
    }
    return subject.save(credentialObject);
  }

  private CertificateCredential saveCertificate(long timeMillis, String credentialName) {
    return saveCertificate(timeMillis, credentialName, null, activeCanaryUuid);
  }

  private CertificateCredential saveCertificateByCa(long timeMillis, String credentialName, String caName) {
    return saveCertificate(timeMillis, credentialName, caName, activeCanaryUuid);
  }


  private void setupTestFixtureForFindMostRecent() {
    CredentialName credentialName = credentialNameDataService
        .save(new CredentialName("/my-CREDENTIAL"));

    namedPasswordCredential1 = new PasswordCredentialVersion();
    namedPasswordCredential1.setCredentialName(credentialName);
    namedPasswordCredential1.setEncryptionKeyUuid(activeCanaryUuid);
    namedPasswordCredential1.setEncryptedValue("/my-old-password".getBytes());
    namedPasswordCredential1.setNonce(new byte[]{});

    passwordCredential2 = new PasswordCredentialVersion();
    passwordCredential2.setCredentialName(credentialName);
    passwordCredential2.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredential2.setEncryptedValue("/my-new-password".getBytes());
    passwordCredential2.setNonce(new byte[]{});

    subject.save(namedPasswordCredential1);
    fakeTimeSetter.accept(345346L); // 1 second later
    subject.save(passwordCredential2);

  }

  private void setupTestFixturesForFindContainingName(String valueName,
      String passwordName,
      String certificateName) {

    fakeTimeSetter.accept(2000000000123L);
    valueCredentialData = new ValueCredentialVersion(valueName);
    valueCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    valueCredentialData.setEncryptedValue("value".getBytes());
    valueCredentialData.setNonce(new byte[]{});
    ValueCredential namedValueCredential = new ValueCredential(valueCredentialData);
    namedValueCredential.setEncryptor(encryptor);
    subject.save(namedValueCredential);

    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("/mySe.cret");
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    new PasswordCredential(passwordCredentialData);
    PasswordCredential namedPasswordCredential;
    subject.save(namedValueCredential);

    fakeTimeSetter.accept(1000000000123L);
    passwordCredentialData = new PasswordCredentialVersion(passwordName);
    passwordCredentialData.setEncryptionKeyUuid(activeCanaryUuid);
    passwordCredentialData.setEncryptedValue("password".getBytes());
    passwordCredentialData.setNonce(new byte[]{});
    namedPasswordCredential = new PasswordCredential(passwordCredentialData);
    subject.save(namedPasswordCredential);

    CertificateCredentialVersion certificateCredentialData = new CertificateCredentialVersion(
        "/myseecret");
    CertificateCredential certificateCredential = new CertificateCredential(
        certificateCredentialData);
    subject.save(certificateCredential);

    fakeTimeSetter.accept(3000000000123L);
    certificateCredentialData = new CertificateCredentialVersion(
        certificateName);
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
