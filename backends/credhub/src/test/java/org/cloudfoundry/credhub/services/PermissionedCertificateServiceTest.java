package org.cloudfoundry.credhub.services;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateDataService;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialFactory;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.permissions.PermissionedCertificateService;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
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
  private PermissionedCertificateService subject;
  private DefaultPermissionedCredentialService permissionedCredentialService;
  private CertificateDataService certificateDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;
  private CertificateVersionDataService certificateVersionDataService;
  private CertificateCredentialFactory certificateCredentialFactory;
  private UUID uuid;
  private CredentialVersionDataService credentialVersionDataService;

  @Before
  public void beforeEach() {
    permissionedCredentialService = mock(DefaultPermissionedCredentialService.class);
    certificateDataService = mock(CertificateDataService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    certificateDataService = mock(CertificateDataService.class);
    userContextHolder = mock(UserContextHolder.class);
    certificateVersionDataService = mock(CertificateVersionDataService.class);
    certificateCredentialFactory = mock(CertificateCredentialFactory.class);
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    subject = new PermissionedCertificateService(
      permissionedCredentialService,
      certificateDataService,
      permissionCheckingService,
      userContextHolder,
      certificateVersionDataService,
      certificateCredentialFactory,
      credentialVersionDataService,
      new CEFAuditRecord()
    );
  }

  @Test
  public void save_whenTransitionalIsFalse_delegatesToPermissionedCredentialService() {
    final CertificateCredentialValue value = mock(CertificateCredentialValue.class);
    when(value.isTransitional()).thenReturn(false);
    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    subject.save(
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

    subject.save(
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
      subject.save(
        mock(CredentialVersion.class),
        value,
        generateRequest
      );
      fail("should throw exception");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.too_many_transitional_versions"));
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

    final List<Credential> certificates = subject.getAll();
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

    final List<Credential> certificates = subject.getByName("my-credential");
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

    uuid = UUID.randomUUID();
    when(certificateVersionDataService.findAllVersions(uuid))
      .thenReturn(versions);

    final List<CredentialVersion> certificates = subject.getVersions(uuid, false);
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

    final List<CredentialVersion> certificates = subject.getVersions(uuid, true);
    assertThat(certificates, equalTo(versions));
  }

  @Test(expected = InvalidQueryParameterException.class)
  public void getVersions_returnsAnError_whenUUIDisInvalid() {
    when(certificateVersionDataService.findAllVersions(uuid)).thenThrow(new IllegalArgumentException());
    subject.getVersions(uuid, false);
  }

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenCredentialDoesNotExist() {
    when(certificateDataService.findByUuid(uuid)).thenReturn(null);
    subject.getVersions(uuid, true);
  }

  @Test(expected = EntryNotFoundException.class)
  public void getVersions_returnsAnError_whenCredentialListisEmpty() {
    when(certificateVersionDataService.findAllVersions(uuid)).thenReturn(Collections.emptyList());
    subject.getVersions(uuid, false);
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

    subject.getVersions(uuid, false);
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

    final CertificateCredentialVersion certificateCredentialVersion = subject
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

    subject.deleteVersion(certificateUuid, versionUuid);
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

    subject.deleteVersion(certificateUuid, versionUuid);
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

    subject.deleteVersion(certificateUuid, versionUuid);
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

    subject.deleteVersion(certificateUuid, versionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void updateTransitionalVersion_whenTheUserDoesNotHavePermissions_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();
    final String credentialName = "my-credential";

    final Credential certificate = mock(Credential.class);
    when(certificate.getName()).thenReturn(credentialName);

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    final String user = "my-user";

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(certificate);
    when(permissionCheckingService.hasPermission(user, credentialName, PermissionOperation.WRITE)).thenReturn(false);

    subject.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void updateTransitionalVersion_whenTheCertificateIsNotFound_returnsAnError() {
    final UUID certificateUuid = UUID.randomUUID();
    final UUID transitionalVersionUuid = UUID.randomUUID();

    final UserContext userContext = mock(UserContext.class);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);

    subject.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
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

    subject.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
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

    subject.updateTransitionalVersion(certificateUuid, transitionalVersionUuid);
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

    subject.set(certificateUuid, mock(CertificateCredentialValue.class));
  }

  @Test(expected = EntryNotFoundException.class)
  public void set_whenTheCredentialDoesNotExist_throwsAnException() {
    final UUID certificateUuid = UUID.randomUUID();

    when(certificateDataService.findByUuid(certificateUuid)).thenReturn(null);
    subject.set(certificateUuid, mock(CertificateCredentialValue.class));
  }
}
