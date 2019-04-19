package org.cloudfoundry.credhub.services;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.data.DefaultCertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.permissions.PermissionedCertificateService;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Fail.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PermissionedCertificateServiceTest {
  private PermissionedCertificateService subjectWithoutConcatenateCas;
  private PermissionedCertificateService subjectWithConcatenateCas;
  private DefaultPermissionedCredentialService permissionedCredentialService;
  private CertificateDataService certificateDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;
  private DefaultCertificateVersionDataService certificateVersionDataService;
  private CertificateCredentialFactory certificateCredentialFactory;
  private UUID uuid;
  private CredentialVersionDataService credentialVersionDataService;

  @Before
  public void beforeEach() {
    uuid = UUID.randomUUID();
    permissionedCredentialService = mock(DefaultPermissionedCredentialService.class);
    certificateDataService = mock(CertificateDataService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    certificateDataService = mock(CertificateDataService.class);
    userContextHolder = mock(UserContextHolder.class);
    certificateVersionDataService = mock(DefaultCertificateVersionDataService.class);
    certificateCredentialFactory = mock(CertificateCredentialFactory.class);
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    subjectWithoutConcatenateCas = new PermissionedCertificateService(
      permissionedCredentialService,
      certificateDataService,
      permissionCheckingService,
      userContextHolder,
      certificateVersionDataService,
      certificateCredentialFactory,
      credentialVersionDataService,
      new CEFAuditRecord(), false
    );
    subjectWithConcatenateCas = new PermissionedCertificateService(
      permissionedCredentialService,
      certificateDataService,
      permissionCheckingService,
      userContextHolder,
      certificateVersionDataService,
      certificateCredentialFactory,
      credentialVersionDataService,
      new CEFAuditRecord(), true
    );
  }

  @Test
  public void save_whenTransitionalIsFalse_delegatesToPermissionedCredentialService() {
    final CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(false);
    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    subjectWithoutConcatenateCas.save(
      mock(CredentialVersion.class),
      value,
      generateRequest
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(permissionedCredentialService).save(any(),
      eq(value),
      eq(generateRequest)
    );
  }

  @Test
  public void save_whenTransitionalIsTrue_andThereAreNoOtherTransitionalVersions_delegatesToPermissionedCredentialService() {
    final CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("/some-name");

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(false);

    when(permissionedCredentialService.findAllByName(eq("/some-name")))
      .thenReturn(newArrayList(previousVersion));

    subjectWithoutConcatenateCas.save(
      mock(CredentialVersion.class),
      value,
      generateRequest
    );

    Mockito.verify(generateRequest).setType(eq("certificate"));
    Mockito.verify(permissionedCredentialService).save(any(),
      eq(value),
      eq(generateRequest)
    );
  }

  @Test
  public void save_whenTransitionalIsTrue_AndThereIsAnotherTransitionalVersion_throwsAnException() {
    final CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(true);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn("/some-name");

    final CertificateCredentialVersion previousVersion = mock(CertificateCredentialVersion.class);
    when(previousVersion.isVersionTransitional()).thenReturn(true);

    when(permissionedCredentialService.findAllByName(eq("/some-name")))
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

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);
    when(permissionCheckingService.hasPermission(user, "your-credential", PermissionOperation.READ)).thenReturn(false);

    when(certificateDataService.findAll())
      .thenReturn(newArrayList(myCredential, yourCredential));

    final List<Credential> certificates = subjectWithoutConcatenateCas.getAll();
    assertThat(certificates, equalTo(newArrayList(myCredential)));
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

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);
    when(permissionCheckingService.hasPermission(user, "other-credential", PermissionOperation.READ)).thenReturn(true);

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

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);

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

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);

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

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenUserDoesntHavePermission() {
    final CredentialVersion myCredential = mock(CredentialVersion.class);
    when(myCredential.getName()).thenReturn("my-credential");
    final CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    final List<CredentialVersion> versions = newArrayList(myCredential, secondVersion);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(false);

    when(certificateVersionDataService.findAllVersions(uuid))
      .thenReturn(versions);

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

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(true);

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

  @Test(expected = EntryNotFoundException.class)
  public void getAllValidVersions_returnsAnError_whenUserDoesntHavePermission() {
    final CredentialVersion firstVersion = mock(CredentialVersion.class);
    when(firstVersion.getName()).thenReturn("my-credential");
    final CredentialVersion secondVersion = mock(CredentialVersion.class);
    when(secondVersion.getName()).thenReturn("my-credential");

    final List<CredentialVersion> versions = newArrayList(firstVersion, secondVersion);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);

    when(permissionCheckingService.hasPermission(user, "my-credential", PermissionOperation.READ)).thenReturn(false);

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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.DELETE)).thenReturn(true);

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

  @Test(expected = EntryNotFoundException.class)
  public void deleteVersion_whenTheUserDoesNotHavePermission_returnsAnError() {
    final UUID versionUuid = UUID.randomUUID();
    final UUID certificateUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";
    when(userContext.getActor()).thenReturn(user);
    final String credentialName = "my-credential";
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.DELETE)).thenReturn(false);

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);
    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);

    final CertificateCredentialVersion versionToDelete = mock(CertificateCredentialVersion.class);
    when(certificate.getUuid()).thenReturn(UUID.randomUUID());
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);
    when(versionToDelete.getCredential()).thenReturn(certificate);

    subjectWithoutConcatenateCas.deleteVersion(certificateUuid, versionUuid);
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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.DELETE)).thenReturn(true);

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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.DELETE)).thenReturn(true);

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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.DELETE)).thenReturn(true);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);

    final CertificateCredentialVersion versionToDelete = mock(CertificateCredentialVersion.class);
    when(certificateVersionDataService.findVersion(versionUuid)).thenReturn(versionToDelete);

    subjectWithoutConcatenateCas.deleteVersion(certificateUuid, versionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void updateTransitionalVersion_whenTheUserDoesNotHavePermissions_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();
    final String credentialName = "my-credential";

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);

    final UserContext userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn("some-actor");
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    when(certificate.getName()).thenReturn(credentialName);
    final String user = "my-user";

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.WRITE)).thenReturn(false);

    subjectWithoutConcatenateCas.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.WRITE)).thenReturn(true);

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
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.WRITE)).thenReturn(true);

    when(certificateVersionDataService.findVersion(transitionalVersionUuid)).thenReturn(version);
    when(version.getCredential()).thenReturn(otherCertificate);

    subjectWithoutConcatenateCas.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void set_whenTheUserDoesNotHavePermission_throwsAnException() {
    final UUID certificateUuid = UUID.randomUUID();
    final String credentialName = "my-credential";

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);

    final String user = "my-user";
    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    when(userContext.getActor()).thenReturn(user);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.WRITE)).thenReturn(false);

    subjectWithoutConcatenateCas.set(certificateUuid, mock(CertificateCredentialValue.class));
  }

  @Test(expected = EntryNotFoundException.class)
  public void set_whenTheCredentialDoesNotExist_throwsAnException() {
    final UUID certificateUuid = UUID.randomUUID();

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);
    subjectWithoutConcatenateCas.set(certificateUuid, mock(CertificateCredentialValue.class));
  }

  @Test
  public void getVersions__whenConcatenateCasIsTrue__returnsConcatenatedCas() {
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

    when(permissionCheckingService.hasPermission(user, "some-cert", PermissionOperation.READ)).thenReturn(true);


    final List<CredentialVersion> results = subjectWithConcatenateCas.getVersions(certUuid, false);
    CertificateCredentialVersion resultCert = (CertificateCredentialVersion) results.get(0);

    List<String> allMatches = new ArrayList<>();
    Matcher m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.getCa());
    while (m.find()) {
      allMatches.add(m.group());
    }
    assertThat(allMatches.size(), equalTo(2));

  }

  @Test
  public void getVersions__whenConcatenateCasIsFalse__returnsSingleCa() {
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

    when(permissionCheckingService.hasPermission(user, "some-cert", PermissionOperation.READ)).thenReturn(true);


    final List<CredentialVersion> results = subjectWithoutConcatenateCas.getVersions(certUuid, false);
    CertificateCredentialVersion resultCert = (CertificateCredentialVersion) results.get(0);

    List<String> allMatches = new ArrayList<>();
    Matcher m = Pattern.compile("BEGIN CERTIFICATE")
            .matcher(resultCert.getCa());
    while (m.find()) {
      allMatches.add(m.group());
    }
    assertThat(allMatches.size(), equalTo(1));
  }

}
