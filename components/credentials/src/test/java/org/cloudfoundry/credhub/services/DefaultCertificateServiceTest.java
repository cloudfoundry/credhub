package org.cloudfoundry.credhub.services;

import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Fail.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCertificateServiceTest {
  private DefaultCertificateService subjectWithoutConcatenateCas;
  private DefaultCertificateService subjectWithConcatenateCas;
  private DefaultCredentialService credentialService;
  private CertificateDataService certificateDataService;
  private UserContextHolder userContextHolder;
  private DefaultCertificateVersionDataService certificateVersionDataService;
  private CertificateCredentialFactory certificateCredentialFactory;
  private UUID uuid;
  private CredentialVersionDataService credentialVersionDataService;
  private UserContext userContext;
  private final static String actor = "Actor";
  private CertificateCredentialVersion childCert;
  private CertificateCredentialVersion nonTransitionalCa;
  private CertificateCredentialVersion transitionalCa;
  private CertificateCredentialVersion newChildCert;
  private UUID certVersionUuid;
  private UUID newCertVersionUuid;
  private UUID caUuid;
  private UUID certUuid;
  private UUID nonTransitionalVersionId;
  private UUID transitionalVersionId;
  private CertificateCredentialValue value;
  private Credential credential;
  private Credential childCredential;

  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    uuid = UUID.randomUUID();
    credentialService = mock(DefaultCredentialService.class);
    certificateDataService = mock(CertificateDataService.class);
    certificateDataService = mock(CertificateDataService.class);
    userContextHolder = mock(UserContextHolder.class);
    certificateVersionDataService = mock(DefaultCertificateVersionDataService.class);
    certificateCredentialFactory = mock(CertificateCredentialFactory.class);
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(actor);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    subjectWithoutConcatenateCas = new DefaultCertificateService(
      credentialService,
      certificateDataService,
      certificateVersionDataService,
      certificateCredentialFactory,
      credentialVersionDataService,
      new CEFAuditRecord(), false
    );
    subjectWithConcatenateCas = new DefaultCertificateService(
      credentialService,
      certificateDataService,
      certificateVersionDataService,
      certificateCredentialFactory,
      credentialVersionDataService,
      new CEFAuditRecord(), true
    );

    certVersionUuid = UUID.randomUUID();
    newCertVersionUuid = UUID.randomUUID();
    caUuid = UUID.randomUUID();
    certUuid = UUID.randomUUID();
    nonTransitionalVersionId = UUID.randomUUID();
    transitionalVersionId = UUID.randomUUID();

    credential = mock(Credential.class);
    when(credential.getName()).thenReturn("some-ca");
    when(credential.getUuid()).thenReturn(caUuid);

    childCredential = mock(Credential.class);
    when(childCredential.getName()).thenReturn("some-cert");
    when(childCredential.getUuid()).thenReturn(certUuid);

    value = mock(CertificateCredentialValue.class);
    when(value.getCa()).thenReturn(TestConstants.TEST_CA);
    when(value.getCertificate()).thenReturn(TestConstants.TEST_CERTIFICATE);
    when(value.getPrivateKey()).thenReturn(TestConstants.TEST_PRIVATE_KEY);
    when(value.getCaName()).thenReturn("some-ca");
    when(value.getGenerated()).thenReturn(true);

    nonTransitionalCa = mock(CertificateCredentialVersion.class);
    when(nonTransitionalCa.getCertificate())
      .thenReturn(TestConstants.TEST_CERTIFICATE);
    when(nonTransitionalCa.isVersionTransitional()).thenReturn(false);
    when(nonTransitionalCa.getName()).thenReturn("some-ca");
    when(nonTransitionalCa.getUuid()).thenReturn(nonTransitionalVersionId);
    when(nonTransitionalCa.getCredential()).thenReturn(credential);

    transitionalCa = mock(CertificateCredentialVersion.class);
    when(transitionalCa.getCertificate())
      .thenReturn(TestConstants.OTHER_TEST_CERTIFICATE);
    when(transitionalCa.isVersionTransitional()).thenReturn(true);
    when(transitionalCa.getName()).thenReturn("some-ca");
    when(transitionalCa.getUuid()).thenReturn(transitionalVersionId);
    when(transitionalCa.getCredential()).thenReturn(credential);

    childCert = mock(CertificateCredentialVersion.class);
    when(childCert.getCaName()).thenReturn("some-ca");
    when(childCert.getCredential()).thenReturn(childCredential);
    when(childCert.getName()).thenReturn("some-cert");
    when(childCert.getUuid()).thenReturn(certVersionUuid);
    when(childCert.getCertificate()).thenReturn(TestConstants.TEST_CERTIFICATE);
    when(childCert.getPrivateKey()).thenReturn(TestConstants.TEST_PRIVATE_KEY);
    when(childCert.getGenerated()).thenReturn(true);
    when(childCert.getValue()).thenReturn(value);


    newChildCert = mock(CertificateCredentialVersion.class);
    when(newChildCert.getCaName()).thenReturn("some-ca");
    when(newChildCert.getName()).thenReturn("some-cert");
    when(newChildCert.getUuid()).thenReturn(newCertVersionUuid);
    when(newChildCert.getValue()).thenReturn(value);
  }

  @Test
  public void save_whenTransitionalIsFalse_delegatesToCredentialService() {
    when(value.isTransitional()).thenReturn(false);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);

    when(credentialService.save(nonTransitionalCa, value, generateRequest))
      .thenReturn(transitionalCa);

    subjectWithoutConcatenateCas.save(
      nonTransitionalCa,
      value,
      generateRequest
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(credentialService).save(any(),
      eq(value),
      eq(generateRequest)
    );
    verify(credentialVersionDataService, Mockito.times(0)).save(any(CertificateCredentialVersion.class));

  }

  @Test
  public void save_whenTransitionalIsTrue_andThereAreNoOtherTransitionalVersions_delegatesToCredentialService() {
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("some-ca");

    when(credentialService.findAllByName(eq("/some-ca")))
      .thenReturn(newArrayList(nonTransitionalCa));

    when(credentialService.save(transitionalCa, value, generateRequest))
      .thenReturn(transitionalCa);

    subjectWithoutConcatenateCas.save(
      transitionalCa,
      value,
      generateRequest
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(credentialService).save(any(),
      eq(value),
      eq(generateRequest)
    );
  }

  @Test
  public void save_whenTransitionalIsTrue_andConcatenateCasIsTrue_generatesNewChildVersion() {
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("some-ca");

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(credentialService.findAllByName(eq("some-ca")))
      .thenReturn(newArrayList(nonTransitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));
    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);
    when(certificateCredentialFactory.makeNewCredentialVersion(eq(childCert.getCredential()), any()))
      .thenReturn(newChildCert);
    when(credentialService.save(nonTransitionalCa, value, generateRequest))
      .thenReturn(transitionalCa);

    subjectWithConcatenateCas.save(
      nonTransitionalCa,
      value,
      generateRequest
    );

    verify(credentialVersionDataService, Mockito.times(1)).save(newChildCert);
  }


  @Test
  public void set_whenTransitionalIsTrue_andConcatenateCasIsTrue_generatesNewChildVersion() {
    when(value.isTransitional()).thenReturn(true);

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(credentialVersionDataService.findActiveByName(childCert.getCaName()))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));

    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);

    when(certificateCredentialFactory.makeNewCredentialVersion(eq(nonTransitionalCa.getCredential()), any()))
      .thenReturn(transitionalCa);
    when(certificateCredentialFactory.makeNewCredentialVersion(eq(childCert.getCredential()), any()))
      .thenReturn(newChildCert);

    when(credentialVersionDataService.save(transitionalCa)).thenReturn(transitionalCa);

    subjectWithConcatenateCas.set(
      caUuid,
      value
    );

    verify(credentialVersionDataService, Mockito.times(1)).save(newChildCert);
  }

  @Test
  public void set_whenTransitionalIsTrue_andConcatenateCasIsFalse_doesNotGeneratesNewChildVersion() {
    when(value.isTransitional()).thenReturn(true);

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(credentialVersionDataService.findActiveByName(childCert.getCaName()))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));

    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);

    when(certificateCredentialFactory.makeNewCredentialVersion(nonTransitionalCa.getCredential(), value))
      .thenReturn(transitionalCa);
    when(certificateCredentialFactory.makeNewCredentialVersion(childCert.getCredential(), (CertificateCredentialValue) childCert.getValue()))
      .thenReturn(newChildCert);

    when(credentialVersionDataService.save(transitionalCa)).thenReturn(transitionalCa);

    subjectWithoutConcatenateCas.set(
      caUuid,
      value
    );

    verify(credentialVersionDataService, Mockito.times(0)).save(newChildCert);
  }


  @Test
  public void save_whenTransitionalIsTrue_andConcatenateCasIsFalse_doesNotGeneratesNewChildVersion() {
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("some-ca");

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(credentialService.findAllByName(eq("some-ca")))
      .thenReturn(newArrayList(nonTransitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));
    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);
    when(certificateCredentialFactory.makeNewCredentialVersion(childCert.getCredential(), (CertificateCredentialValue) childCert.getValue()))
      .thenReturn(newChildCert);
    when(credentialService.save(nonTransitionalCa, value, generateRequest))
      .thenReturn(transitionalCa);

    subjectWithoutConcatenateCas.save(
      nonTransitionalCa,
      value,
      generateRequest
    );

    verify(credentialVersionDataService, Mockito.times(0)).save(newChildCert);
  }


  @Test
  public void save_whenTransitionalIsTrue_AndThereIsAnotherTransitionalVersion_throwsAnException() {
    final CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("/some-name");

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(true);

    when(credentialService.findAllByName(eq("/some-name")))
      .thenReturn(newArrayList(previousVersion));

    try {
      subjectWithoutConcatenateCas.save(
        mock(CredentialVersion.class),
        value,
        generateRequest
      );
      fail("should throw exception");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.TOO_MANY_TRANSITIONAL_VERSIONS));
    }
  }

  @Test
  public void getAll_returnsAllCertificatesTheCurrentUserCanAccess() {
    final Credential myCredential = mock(Credential.class);
    when(myCredential.getName()).thenReturn("my-credential");
    final Credential yourCredential = mock(Credential.class);
    when(yourCredential.getName()).thenReturn("your-credential");

    when(certificateDataService.findAll())
      .thenReturn(newArrayList(myCredential, yourCredential));

    final List<Credential> certificates = subjectWithoutConcatenateCas.getAll();
    assertThat(certificates, equalTo(newArrayList(myCredential, yourCredential)));
  }

  @Test
  public void getAllByName_returnsCertificateWithMatchingNameIfCurrentUserHasAccess() {
    final Credential myCredential = mock(Credential.class);
    when(myCredential.getName()).thenReturn("my-credential");
    final Credential otherCredential = mock(Credential.class);
    when(otherCredential.getName()).thenReturn("other-credential");

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByName("my-credential"))
      .thenReturn(myCredential);

    final List<Credential> certificates = subjectWithoutConcatenateCas.getByName("my-credential");
    assertThat(certificates, equalTo(newArrayList(myCredential)));
  }

  @Test
  public void getVersions_returnsListWithVersions() {
    final CredentialVersion myCredential = mock(CredentialVersion.class);
    when(myCredential.getName()).thenReturn("my-credential");
    final CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    final List<CredentialVersion> versions = newArrayList(myCredential, secondVersion);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);


    when(certificateVersionDataService.findAllVersions(uuid))
      .thenReturn(versions);

    final List<CredentialVersion> certificates = subjectWithoutConcatenateCas.getVersions(uuid, false);
    assertThat(certificates, equalTo(versions));
  }

  @Test
  public void getVersions_withCurrentTrue_returnsCurrentVersions() {
    final Credential aCredential = new Credential("my-credential");

    final CredentialVersion credentialVersion1 = mock(CredentialVersion.class);
    when(credentialVersion1.getName()).thenReturn("my-credential");
    final CredentialVersion credentialVersion2 = mock(CredentialVersion.class);
    when(credentialVersion2.getName()).thenReturn("my-credential");

    final List<CredentialVersion> versions = newArrayList(credentialVersion1, credentialVersion2);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByUuid(uuid))
      .thenReturn(aCredential);
    when(certificateVersionDataService.findActiveWithTransitional("my-credential"))
      .thenReturn(versions);

    final List<CredentialVersion> certificates = subjectWithoutConcatenateCas.getVersions(uuid, true);
    assertThat(certificates, equalTo(versions));
  }

  @Test(expected = InvalidQueryParameterException.class)
  public void getVersions_returnsAnError_whenUUIDisInvalid() {
    when(certificateVersionDataService.findAllVersions(uuid)).thenThrow(new IllegalArgumentException());
    subjectWithoutConcatenateCas.getVersions(uuid, false);
  }

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenCredentialDoesNotExist() {
    when(certificateDataService.findByUuid(uuid)).thenReturn(null);
    subjectWithoutConcatenateCas.getVersions(uuid, true);
  }

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenCredentialListisEmpty() {
    when(certificateVersionDataService.findAllVersions(uuid)).thenReturn(Collections.emptyList());
    subjectWithoutConcatenateCas.getVersions(uuid, false);
  }

  @Test
  public void getAllValidVersions_returnsListWithValidVersions() {
    final CredentialVersion firstVersion = mock(CredentialVersion.class);
    when(firstVersion.getName()).thenReturn("my-credential");
    final CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    final List<CredentialVersion> versions = newArrayList(firstVersion, secondVersion);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);


    when(certificateVersionDataService.findAllValidVersions(uuid))
      .thenReturn(versions);

    final List<CredentialVersion> certificates = subjectWithoutConcatenateCas.getAllValidVersions(uuid);
    assertThat(certificates, equalTo(versions));
  }

  @Test(expected = InvalidQueryParameterException.class)
  public void getAllValidVersions_returnsAnError_whenUUIDisInvalid() {
    when(certificateVersionDataService.findAllValidVersions(uuid)).thenThrow(new IllegalArgumentException());
    subjectWithoutConcatenateCas.getAllValidVersions(uuid);
  }

  @Test
  public void getAllValidVersions_returnsAnEmptyList_whenCredentialListIsEmpty() {
    when(certificateVersionDataService.findAllValidVersions(uuid)).thenReturn(Collections.emptyList());
    assertThat(subjectWithoutConcatenateCas.getAllValidVersions(uuid).size(), equalTo(0));
  }

  @Test(expected = EntryNotFoundException.class)
  public void getAllValidVersions_returnsAnError_whenCredentialNameIsNull() {
    final CredentialVersion versionWithNoName = mock(CredentialVersion.class);
    when(versionWithNoName.getName()).thenReturn(null);

    final List<CredentialVersion> versions = newArrayList(versionWithNoName);

    when(certificateVersionDataService.findAllValidVersions(uuid))
      .thenReturn(versions);

    subjectWithoutConcatenateCas.getAllValidVersions(uuid);
  }

  @Test
  public void deleteVersion_deletesTheProvidedVersion() {
    final UUID versionUuid = UUID.randomUUID();
    final UUID certificateUuid = UUID.randomUUID();

    final CertificateCredentialVersion versionToDelete = mock(CertificateCredentialVersion.class);
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";
    final String credentialName = "my-credential";
    when(userContext.getActor()).thenReturn(user);

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    when(certificate.getUuid()).thenReturn(UUID.randomUUID());
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);
    when(versionToDelete.getCredential()).thenReturn(certificate);

    final CertificateCredentialVersion certificateCredentialVersion = subjectWithoutConcatenateCas
      .deleteVersion(certificateUuid, versionUuid);

    assertThat(certificateCredentialVersion, equalTo(versionToDelete));
  }

  @Test
  public void deleteVersion_whenVersionIsTransitional_generatesNewChildVersion() {
    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(certificateVersionDataService.findVersion(transitionalVersionId))
      .thenReturn(transitionalCa);
    when(credentialService.findAllByName(eq("some-ca")))
      .thenReturn(newArrayList(nonTransitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));
    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);
    when(certificateCredentialFactory.makeNewCredentialVersion(eq(childCert.getCredential()), any()))
      .thenReturn(newChildCert);

    subjectWithConcatenateCas
      .deleteVersion(caUuid, transitionalVersionId);

    verify(credentialVersionDataService, Mockito.times(1)).save(newChildCert);

  }

  @Test
  public void deleteVersion_whenVersionIsNotTransitional_doesNotGeneratesNewChildVersion() {
    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(certificateVersionDataService.findVersion(nonTransitionalVersionId))
      .thenReturn(nonTransitionalCa);

    subjectWithConcatenateCas
      .deleteVersion(caUuid, nonTransitionalVersionId);

    verify(credentialVersionDataService, Mockito.times(0)).save(newChildCert);
  }


  @Test(expected = EntryNotFoundException.class)
  public void deleteVersion_whenTheProvidedVersionDoesNotExistForTheSpecifiedCredential_returnsAnError() {
    final UUID versionUuid = UUID.randomUUID();
    final UUID certificateUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";
    final String credentialName = "my-credential";
    when(userContext.getActor()).thenReturn(user);

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificate.getUuid()).thenReturn(certificateUuid);
    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    final CertificateCredentialVersion versionToDelete = mock(CertificateCredentialVersion.class);
    final Credential someOtherCredential = mock(Credential.class);
    when(certificate.getUuid()).thenReturn(UUID.randomUUID());
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);
    when(versionToDelete.getCredential()).thenReturn(someOtherCredential);

    subjectWithoutConcatenateCas.deleteVersion(certificateUuid, versionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void deleteVersion_whenTheProvidedVersionDoesNotExist_returnsAnError() {
    final UUID versionUuid = UUID.randomUUID();
    final UUID certificateUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";
    final String credentialName = "my-credential";
    when(userContext.getActor()).thenReturn(user);

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificate.getUuid()).thenReturn(certificateUuid);
    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    when(certificate.getUuid()).thenReturn(UUID.randomUUID());
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(null);

    subjectWithoutConcatenateCas.deleteVersion(certificateUuid, versionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void deleteVersion_whenTheProvidedCredentialDoesNotExist_returnsAnError() {
    final UUID versionUuid = UUID.randomUUID();
    final UUID certificateUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";
    final String credentialName = "my-credential";
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);

    final CertificateCredentialVersion versionToDelete = mock(CertificateCredentialVersion.class);
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);

    subjectWithoutConcatenateCas.deleteVersion(certificateUuid, versionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void updateTransitionalVersion_whenTheCertificateIsNotFound_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);

    subjectWithoutConcatenateCas.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void updateTransitionalVersion_whenVersionDoesNotExist_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();
    final String credentialName = "my-credential";

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificate.getUuid()).thenReturn(certificateUuid);

    final String user = "my-user";
    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    when(certificateVersionDataService.findVersion(transitionalVersionUuid)).thenReturn(null);

    subjectWithoutConcatenateCas.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void updateTransitionalVersion_whenVersionDoesNotBelongToCertificate_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();
    final String credentialName = "my-credential";

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificate.getUuid()).thenReturn(certificateUuid);

    final Credential otherCertificate = mock(Credential.class);
    when(otherCertificate.getUuid()).thenReturn(UUID.randomUUID());

    final CertificateCredentialVersion version = mock(CertificateCredentialVersion.class);

    final String user = "my-user";
    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    when(certificateVersionDataService.findVersion(transitionalVersionUuid)).thenReturn(version);
    when(version.getCredential()).thenReturn(otherCertificate);

    subjectWithoutConcatenateCas.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void set_whenTheCredentialDoesNotExist_throwsAnException() {
    final UUID certificateUuid = UUID.randomUUID();

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);
    subjectWithoutConcatenateCas.set(certificateUuid, mock(CertificateCredentialValue.class));
  }

  @Test
  public void updateTransitionalVersion__whenConcatenateCasIsTrue__generatesNewChildVersion() {
    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(credentialVersionDataService.findActiveByName(childCert.getCaName()))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));
    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);
    when(certificateCredentialFactory.makeNewCredentialVersion(eq(childCert.getCredential()), any()))
      .thenReturn(newChildCert);
    when(certificateVersionDataService.findVersion(nonTransitionalVersionId))
      .thenReturn(nonTransitionalCa);

    subjectWithConcatenateCas.updateTransitionalVersion(caUuid, nonTransitionalVersionId);

    verify(credentialVersionDataService, Mockito.times(1)).save(newChildCert);
  }

  @Test
  public void updateTransitionalVersion__whenConcatenateCasIsFalse__doesNotGenerateNewChildVersion() {
    when(certificateDataService.findByUuid(caUuid)).thenReturn(credential);
    when(credentialVersionDataService.findActiveByName(childCert.getCaName()))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(certificateVersionDataService.findActiveWithTransitional("some-ca"))
      .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(credentialService.findAllCertificateCredentialsByCaName("some-ca"))
      .thenReturn(Collections.singletonList("some-cert"));
    when(credentialVersionDataService.findMostRecent(childCert.getName()))
      .thenReturn(childCert);
    when(certificateCredentialFactory.makeNewCredentialVersion(childCert.getCredential(), (CertificateCredentialValue) childCert.getValue()))
      .thenReturn(newChildCert);
    when(certificateVersionDataService.findVersion(nonTransitionalVersionId))
      .thenReturn(nonTransitionalCa);

    subjectWithoutConcatenateCas.updateTransitionalVersion(caUuid, nonTransitionalVersionId);

    verify(credentialVersionDataService, Mockito.times(0)).save(newChildCert);
  }

  @Test
  public void getVersions__whenConcatenateCasIsTrue__returnsSingleCa() {
    UUID certUuid = UUID.randomUUID();
    CertificateCredentialVersion nonTransitionalCa = mock(CertificateCredentialVersion.class);
    when(nonTransitionalCa.getCertificate())
            .thenReturn(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion transitionalCa = mock(CertificateCredentialVersion.class);
    when(transitionalCa.getCertificate())
            .thenReturn(TestConstants.OTHER_TEST_CERTIFICATE);

    CertificateCredentialVersion certificate = new CertificateCredentialVersion("some-cert");
    certificate.setCaName("testCa");
    certificate.getCredential().setUuid(certUuid);
    certificate.setUuid(certUuid);
    certificate.setCa(TestConstants.TEST_CERTIFICATE);
    when(credentialVersionDataService.findActiveByName(certificate.getCaName()))
            .thenReturn(Arrays.asList(nonTransitionalCa, transitionalCa));
    when(certificateVersionDataService.findAllVersions(certUuid))
            .thenReturn(Collections.singletonList(certificate));

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    final List<CredentialVersion> results = subjectWithConcatenateCas.getVersions(certUuid, false);
    CertificateCredentialVersion resultCert = (CertificateCredentialVersion) results.get(0);

    List<String> allMatches = new ArrayList<>();
    Matcher m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.getCa());
    while (m.find()) {
      allMatches.add(m.group());
    }
    assertThat(allMatches.size(), equalTo(1));
  }

  @Test
  public void findByUuid_ReturnsCertificateWithMatchingUuid() {
    final CredentialVersion credentialVersion = new CertificateCredentialVersion();
    credentialVersion.createName("credential-name");
    String credentialUuid = UUID.randomUUID().toString();
    when(certificateVersionDataService.findByCredentialUUID(credentialUuid)).thenReturn(credentialVersion);


    final CertificateCredentialVersion certificate = subjectWithoutConcatenateCas.findByCredentialUuid(credentialUuid);

    assertThat(certificate, not(nullValue()));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidNotFound() {
    when(certificateVersionDataService.findByCredentialUUID("UnknownUuid")).thenReturn(null);

    subjectWithoutConcatenateCas.findByCredentialUuid("UnknownUuid");
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidMatchesNonCertificateCredential() {
    when(certificateVersionDataService.findByCredentialUUID("rsaUuid")).thenReturn(null);

    subjectWithoutConcatenateCas.findByCredentialUuid("rsaUuid");
  }

}
