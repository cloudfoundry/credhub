package org.cloudfoundry.credhub.handlers;

import java.security.Security;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.certificates.DefaultCertificatesHandler;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator;
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.requests.CreateVersionRequest;
import org.cloudfoundry.credhub.requests.UpdateTransitionalVersionRequest;
import org.cloudfoundry.credhub.services.DefaultCertificateService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.cloudfoundry.credhub.views.CertificateCredentialView;
import org.cloudfoundry.credhub.views.CertificateCredentialsView;
import org.cloudfoundry.credhub.views.CertificateView;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.Test;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.emptySet;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCertificatesHandlerTest {

  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final String UUID_STRING = UUID.randomUUID().toString();
  private static final String USER = "darth-sirius";

  private DefaultCertificatesHandler subjectWithAcls;
  private DefaultCertificatesHandler subjectWithoutAcls;
  private UniversalCredentialGenerator universalCredentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private DefaultCertificateService certificateService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;
  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    permissionCheckingService = mock(PermissionCheckingService.class);
    userContextHolder = mock(UserContextHolder.class);
    UserContext userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(USER);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
    certificateService = mock(DefaultCertificateService.class);
    universalCredentialGenerator = mock(UniversalCredentialGenerator.class);
    generationRequestGenerator = mock(GenerationRequestGenerator.class);
    subjectWithAcls = new DefaultCertificatesHandler(
      certificateService,
      universalCredentialGenerator,
      generationRequestGenerator,
      new CEFAuditRecord(),
      permissionCheckingService,
      userContextHolder,
      true
    );
    subjectWithoutAcls = new DefaultCertificatesHandler(
      certificateService,
      universalCredentialGenerator,
      generationRequestGenerator,
      new CEFAuditRecord(),
      permissionCheckingService,
      userContextHolder,
      false
    );
  }

  @Test
  public void handleGetAllRequest_returnsCertificateCredentialsView() {
    final Credential certWithCaAndChildren = mock(Credential.class);
    final UUID certWithCaAndChildrenUuid = UUID.randomUUID();
    final String certWithCaAndChildrenName = "/certWithCaAndChildren";
    final String certWithCaAndChildrenCaName = "/testCa";
    final List<String> childCertNames = asList("childCert1", "childCert2");
    when(certWithCaAndChildren.getUuid()).thenReturn(certWithCaAndChildrenUuid);
    when(certWithCaAndChildren.getName()).thenReturn(certWithCaAndChildrenName);

    final Credential selfSignedCert = mock(Credential.class);
    final UUID selfSignedCertUuid = UUID.randomUUID();
    final String selfSignedCertName = "/selfSignedCert";
    when(selfSignedCert.getUuid()).thenReturn(selfSignedCertUuid);
    when(selfSignedCert.getName()).thenReturn(selfSignedCertName);

    final Credential noPermissionCert = mock(Credential.class);
    final UUID noPermissionCertUuid = UUID.randomUUID();
    final String noPermissionCertName = "/noPermissionCert";
    when(noPermissionCert.getUuid()).thenReturn(noPermissionCertUuid);
    when(noPermissionCert.getName()).thenReturn(noPermissionCertName);

    final UUID certificateWithNoValidVersionsUuid = UUID.randomUUID();
    final Credential certificateWithNoValidVersions = mock(Credential.class);
    when(certificateWithNoValidVersions.getName()).thenReturn("/notValid");
    when(certificateWithNoValidVersions.getUuid()).thenReturn(certificateWithNoValidVersionsUuid);

    final CertificateCredentialVersion certWithCaAndChildrenVersion = new CertificateCredentialVersion(certWithCaAndChildrenName);
    certWithCaAndChildrenVersion.setUuid(UUID.randomUUID());
    certWithCaAndChildrenVersion.setExpiryDate(Instant.now());
    certWithCaAndChildrenVersion.setCaName(certWithCaAndChildrenCaName);
    certWithCaAndChildrenVersion.setCertificate(TestConstants.TEST_CERTIFICATE);

    final CertificateCredentialVersion selfSignedCertVersion = new CertificateCredentialVersion(selfSignedCertName);
    selfSignedCertVersion.setUuid(UUID.randomUUID());
    selfSignedCertVersion.setExpiryDate(Instant.now());
    selfSignedCertVersion.setCertificate(TestConstants.TEST_CA);

    final HashSet<String> allowedPaths = new HashSet<>(asList("/certWithCaAndChildren", "/selfSignedCert", "/notValid"));

    when(certificateService.getAll())
      .thenReturn(asList(certWithCaAndChildren, selfSignedCert, certificateWithNoValidVersions, noPermissionCert));

    when(certificateService.getAllValidVersions(certWithCaAndChildrenUuid))
      .thenReturn(Collections.singletonList(certWithCaAndChildrenVersion));

    when(certificateService.findSignedCertificates(certWithCaAndChildrenName))
      .thenReturn(childCertNames);

    when(certificateService.getAllValidVersions(selfSignedCertUuid))
      .thenReturn(Collections.singletonList(selfSignedCertVersion));

    when(certificateService.findSignedCertificates(selfSignedCertName))
      .thenReturn(emptyList());

    when(certificateService.getAllValidVersions(certificateWithNoValidVersionsUuid))
      .thenReturn(emptyList());

    when(permissionCheckingService.findAllPathsByActor(USER))
      .thenReturn(allowedPaths);

    final CertificateCredentialsView certificateCredentialsView = subjectWithAcls.handleGetAllRequest();

    final CertificateCredentialView actualCertWithCa = certificateCredentialsView.getCertificates().get(0);
    final CertificateCredentialView actualSelfSignedCert = certificateCredentialsView.getCertificates().get(1);
    final CertificateCredentialView actualCertificateWithNoValidVersions = certificateCredentialsView.getCertificates().get(2);

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(3));
    assertThat(actualCertWithCa.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualCertWithCa.getSignedBy(), equalTo(certWithCaAndChildrenCaName));
    assertThat(actualSelfSignedCert.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualSelfSignedCert.getSignedBy(), equalTo(selfSignedCertName));
    assertThat(actualCertificateWithNoValidVersions.getCertificateVersionViews().size(), equalTo(0));
    assertThat(actualCertificateWithNoValidVersions.getSignedBy(), equalTo(""));
  }

  @Test
  public void handleGetAllRequest_whenUserLacksPermission_returnsEmptyList() {
    when(permissionCheckingService.findAllPathsByActor(USER))
      .thenReturn(emptySet());

    CertificateCredentialsView certificateCredentialsView = subjectWithAcls.handleGetAllRequest();
    assertEquals(certificateCredentialsView.getCertificates().size(), 0);

  }

  @Test
  public void handleGetAllRequest_whenAclsDisabled_doesNotCheckPermissions_andReturnsCertificateCredentialsView() {
    final Credential certWithCaAndChildren = mock(Credential.class);
    final UUID certWithCaAndChildrenUuid = UUID.randomUUID();
    final String certWithCaAndChildrenName = "/certWithCaAndChildren";
    final String certWithCaAndChildrenCaName = "/testCa";
    final List<String> childCertNames = asList("childCert1", "childCert2");
    when(certWithCaAndChildren.getUuid()).thenReturn(certWithCaAndChildrenUuid);
    when(certWithCaAndChildren.getName()).thenReturn(certWithCaAndChildrenName);

    final Credential selfSignedCert = mock(Credential.class);
    final UUID selfSignedCertUuid = UUID.randomUUID();
    final String selfSignedCertName = "/selfSignedCert";
    when(selfSignedCert.getUuid()).thenReturn(selfSignedCertUuid);
    when(selfSignedCert.getName()).thenReturn(selfSignedCertName);

    final Credential noPermissionCert = mock(Credential.class);
    final UUID noPermissionCertUuid = UUID.randomUUID();
    final String noPermissionCertName = "/noPermissionCert";
    when(noPermissionCert.getUuid()).thenReturn(noPermissionCertUuid);
    when(noPermissionCert.getName()).thenReturn(noPermissionCertName);

    final UUID certificateWithNoValidVersionsUuid = UUID.randomUUID();
    final Credential certificateWithNoValidVersions = mock(Credential.class);
    when(certificateWithNoValidVersions.getName()).thenReturn("/notValid");
    when(certificateWithNoValidVersions.getUuid()).thenReturn(certificateWithNoValidVersionsUuid);

    final CertificateCredentialVersion certWithCaAndChildrenVersion = new CertificateCredentialVersion(certWithCaAndChildrenName);
    certWithCaAndChildrenVersion.setUuid(UUID.randomUUID());
    certWithCaAndChildrenVersion.setExpiryDate(Instant.now());
    certWithCaAndChildrenVersion.setCaName(certWithCaAndChildrenCaName);
    certWithCaAndChildrenVersion.setCertificate(TestConstants.TEST_CERTIFICATE);

    final CertificateCredentialVersion selfSignedCertVersion = new CertificateCredentialVersion(selfSignedCertName);
    selfSignedCertVersion.setUuid(UUID.randomUUID());
    selfSignedCertVersion.setExpiryDate(Instant.now());
    selfSignedCertVersion.setCertificate(TestConstants.TEST_CA);

    when(certificateService.getAll())
      .thenReturn(asList(certWithCaAndChildren, selfSignedCert, certificateWithNoValidVersions, noPermissionCert));

    when(certificateService.getAllValidVersions(certWithCaAndChildrenUuid))
      .thenReturn(Collections.singletonList(certWithCaAndChildrenVersion));

    when(certificateService.findSignedCertificates(certWithCaAndChildrenName))
      .thenReturn(childCertNames);

    when(certificateService.getAllValidVersions(selfSignedCertUuid))
      .thenReturn(Collections.singletonList(selfSignedCertVersion));

    when(certificateService.findSignedCertificates(selfSignedCertName))
      .thenReturn(emptyList());

    when(certificateService.getAllValidVersions(certificateWithNoValidVersionsUuid))
      .thenReturn(emptyList());

    final CertificateCredentialsView certificateCredentialsView = subjectWithoutAcls.handleGetAllRequest();

    final CertificateCredentialView actualCertWithCa = certificateCredentialsView.getCertificates().get(0);
    final CertificateCredentialView actualSelfSignedCert = certificateCredentialsView.getCertificates().get(1);
    final CertificateCredentialView actualCertificateWithNoValidVersions = certificateCredentialsView.getCertificates().get(2);

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(4));
    assertThat(actualCertWithCa.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualCertWithCa.getSignedBy(), equalTo(certWithCaAndChildrenCaName));
    assertThat(actualSelfSignedCert.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualSelfSignedCert.getSignedBy(), equalTo(selfSignedCertName));
    assertThat(actualCertificateWithNoValidVersions.getCertificateVersionViews().size(), equalTo(0));
    assertThat(actualCertificateWithNoValidVersions.getSignedBy(), equalTo(""));

    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void handleGetByNameRequest_returnsCertificateCredentialsViews() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some certificate";
    final String caName = "/testCa";
    final List<String> childCertNames = asList("certName1", "certName2");

    final Credential credential = mock(Credential.class);
    when(credential.getUuid()).thenReturn(uuid);
    when(credential.getName()).thenReturn(certificateName);

    when(certificateService.getByName(certificateName))
      .thenReturn(Collections.singletonList(credential));

    when(permissionCheckingService.hasPermission(USER, certificateName, PermissionOperation.READ))
      .thenReturn(true);

    final CertificateCredentialVersion nonTransitionalVersion = new CertificateCredentialVersion(certificateName);
    nonTransitionalVersion.setUuid(UUID.randomUUID());
    nonTransitionalVersion.setExpiryDate(Instant.now());
    nonTransitionalVersion.setCaName(caName);
    nonTransitionalVersion.setTransitional(false);
    nonTransitionalVersion.setCertificate(TestConstants.TEST_CERTIFICATE);
    final CertificateCredentialVersion transitionalVersion = new CertificateCredentialVersion(certificateName);
    transitionalVersion.setUuid(UUID.randomUUID());
    transitionalVersion.setExpiryDate(Instant.now());
    transitionalVersion.setTransitional(true);

    when(certificateService.getAllValidVersions(uuid))
      .thenReturn(asList(nonTransitionalVersion, transitionalVersion));
    when(certificateService.findSignedCertificates(certificateName))
      .thenReturn(childCertNames);

    final CertificateCredentialsView certificateCredentialsView = subjectWithAcls.handleGetByNameRequest(certificateName);

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(1));

    final CertificateCredentialView certificate = certificateCredentialsView.getCertificates().get(0);
    assertThat(certificate.getCertificateVersionViews().size(), equalTo(2));
    assertThat(certificate.getSignedBy(), equalTo(caName));
    assertThat(certificate.getSigns(), equalTo(childCertNames));
  }

  @Test
  public void handleGetByNameRequest_whenUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.handleGetByNameRequest(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(0)).getByName(any());
  }

  @Test
  public void handleGetByNameRequest_whenAclsDisabled_doesNotCheckPermissions() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some certificate";
    final String caName = "/testCa";
    final List<String> childCertNames = asList("certName1", "certName2");

    final Credential credential = mock(Credential.class);
    when(credential.getUuid()).thenReturn(uuid);
    when(credential.getName()).thenReturn(certificateName);

    when(certificateService.getByName(certificateName))
      .thenReturn(Collections.singletonList(credential));

    final CertificateCredentialVersion nonTransitionalVersion = new CertificateCredentialVersion(certificateName);
    nonTransitionalVersion.setUuid(UUID.randomUUID());
    nonTransitionalVersion.setExpiryDate(Instant.now());
    nonTransitionalVersion.setCaName(caName);
    nonTransitionalVersion.setTransitional(false);
    nonTransitionalVersion.setCertificate(TestConstants.TEST_CERTIFICATE);
    final CertificateCredentialVersion transitionalVersion = new CertificateCredentialVersion(certificateName);
    transitionalVersion.setUuid(UUID.randomUUID());
    transitionalVersion.setExpiryDate(Instant.now());
    transitionalVersion.setTransitional(true);

    when(certificateService.getAllValidVersions(uuid))
      .thenReturn(asList(nonTransitionalVersion, transitionalVersion));
    when(certificateService.findSignedCertificates(certificateName))
      .thenReturn(childCertNames);

    CertificateCredentialsView certificateCredentialsView = subjectWithoutAcls.handleGetByNameRequest(certificateName);
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(1));

    final CertificateCredentialView certificate = certificateCredentialsView.getCertificates().get(0);
    assertThat(certificate.getCertificateVersionViews().size(), equalTo(2));
    assertThat(certificate.getSignedBy(), equalTo(caName));
    assertThat(certificate.getSigns(), equalTo(childCertNames));
  }

  @Test
  public void handleGetAllVersionsRequest_returnsListOfCertificateViews() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some certificate";
    CertificateCredentialVersion credential = new CertificateCredentialVersion(certificateName);
    when(certificateService.findByCredentialUuid(uuid.toString())).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, certificateName, PermissionOperation.READ))
      .thenReturn(true);

    final CredentialVersion credentialVersion = new CertificateCredentialVersion(certificateName);
    when(certificateService.getVersions(uuid, false))
      .thenReturn(Collections.singletonList(credentialVersion));
    final List<CertificateView> certificateViews = subjectWithAcls
      .handleGetAllVersionsRequest(uuid.toString(), false);

    assertThat(certificateViews.size(), equalTo(1));
    assertThat(certificateViews.get(0).getName(), equalTo(certificateName));
  }

  @Test
  public void handleGetAllVersionsRequest_whenUserLacksPermission_throwsException() {
    CertificateCredentialVersion credential = new CertificateCredentialVersion(CREDENTIAL_NAME);
    when(certificateService.findByCredentialUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.handleGetAllVersionsRequest(UUID_STRING, true);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(0)).getVersions(UUID.fromString(UUID_STRING), true);
  }

  @Test
  public void handleGetAllVersionsRequest_whenAclsDisabled_doesNotCheckPermissions() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some-certificate";
    CertificateCredentialVersion credential = new CertificateCredentialVersion(certificateName);
    when(certificateService.findByCredentialUuid(uuid.toString())).thenReturn(credential);

    final CredentialVersion credentialVersion = new CertificateCredentialVersion(certificateName);
    when(certificateService.getVersions(uuid, false))
      .thenReturn(Collections.singletonList(credentialVersion));
    List<CertificateView> certificateViews = subjectWithoutAcls
      .handleGetAllVersionsRequest(uuid.toString(), false);

    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
    assertThat(certificateViews.size(), equalTo(1));
    assertThat(certificateViews.get(0).getName(), equalTo(certificateName));
  }

  @Test
  public void handleRegenerate_passesOnTransitionalFlagWhenRegeneratingCertificate() {
    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    final CertificateCredentialValue newValue = mock(CertificateCredentialValue.class);

    when(certificate.getName()).thenReturn("test");
    when(permissionCheckingService.hasPermission(USER, "test", PermissionOperation.WRITE))
      .thenReturn(true);
    when(certificateService.findByCredentialUuid(eq(UUID_STRING))).thenReturn(certificate);
    when(generationRequestGenerator.createGenerateRequest(eq(certificate)))
      .thenReturn(generateRequest);
    when(universalCredentialGenerator.generate(eq(generateRequest))).thenReturn(newValue);
    when(certificateService.save(eq(certificate), any(), any()))
      .thenReturn(mock(CertificateCredentialVersion.class));

    final CertificateRegenerateRequest regenerateRequest = new CertificateRegenerateRequest(true);

    subjectWithAcls.handleRegenerate(UUID_STRING, regenerateRequest);

    verify(newValue).setTransitional(true);
  }

  @Test
  public void handleRegenerate_whenUserLacksPermission_throwsException() {
    CertificateCredentialVersion credential = new CertificateCredentialVersion(CREDENTIAL_NAME);
    when(certificateService.findByCredentialUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAcls.handleRegenerate(UUID_STRING, new CertificateRegenerateRequest());
      fail("should throw exception");
    } catch (final PermissionException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(1)).findByCredentialUuid(any());
    verify(generationRequestGenerator, times(0)).createGenerateRequest(any());
    verify(universalCredentialGenerator, times(0)).generate(any());
    verify(certificateService, times(0)).save(any(), any(), any());
  }

  @Test
  public void handleRegenerate_whenAclsDisabled_doesNotCheckPermissions_andPassesOnTransitionalFlagWhenRegeneratingCertificate() {
    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    final CertificateCredentialValue newValue = mock(CertificateCredentialValue.class);

    when(certificate.getName()).thenReturn("test");

    when(certificateService.findByCredentialUuid(eq(UUID_STRING))).thenReturn(certificate);
    when(generationRequestGenerator.createGenerateRequest(eq(certificate)))
      .thenReturn(generateRequest);
    when(universalCredentialGenerator.generate(eq(generateRequest))).thenReturn(newValue);
    when(certificateService.save(eq(certificate), any(), any()))
      .thenReturn(mock(CertificateCredentialVersion.class));

    final CertificateRegenerateRequest regenerateRequest = new CertificateRegenerateRequest(true);

    subjectWithoutAcls.handleRegenerate(UUID_STRING, regenerateRequest);

    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
    verify(newValue).setTransitional(true);
  }

  @Test
  public void handleDeleteVersionRequest_whenAclsEnabled_andHasUserPermission_deletesVersion() {
    UUID versionId = UUID.randomUUID();
    UUID certificateId = UUID.randomUUID();

    final Credential credential = mock(Credential.class);
    when(credential.getName()).thenReturn(CREDENTIAL_NAME);
    when(credential.getUuid()).thenReturn(certificateId);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);
    when(certificate.getUuid()).thenReturn(versionId);
    when(certificate.getCredential()).thenReturn(credential);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
      .thenReturn(true);

    when(certificateService.findByCredentialUuid(certificateId.toString())).thenReturn(certificate);

    when(certificateService.deleteVersion(certificateId, versionId))
      .thenReturn(certificate);

    final CertificateView certificateView = subjectWithAcls.handleDeleteVersionRequest(certificateId.toString(), versionId.toString());

    assertEquals(versionId.toString(), certificateView.getUuid());
    assertEquals(CREDENTIAL_NAME, certificateView.getName());

    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE);
    verify(certificateService, times(1)).deleteVersion(certificateId, versionId);
  }

  @Test
  public void handleDeleteVersionRequest_whenUserLacksPermission_throwsException() {
    CertificateCredentialVersion credential = new CertificateCredentialVersion(CREDENTIAL_NAME);
    when(certificateService.findByCredentialUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
      .thenReturn(false);

    try {
      subjectWithAcls.handleDeleteVersionRequest(UUID_STRING, UUID.randomUUID().toString());
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(0)).deleteVersion(any(), any());
  }

  @Test
  public void handleDeleteVersionRequest_whenAclsDisabled_doesntCheckPermission_andDeletesVersion() {
    UUID versionId = UUID.randomUUID();
    UUID certificateId = UUID.randomUUID();

    final Credential credential = mock(Credential.class);
    when(credential.getName()).thenReturn(CREDENTIAL_NAME);
    when(credential.getUuid()).thenReturn(certificateId);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);
    when(certificate.getUuid()).thenReturn(versionId);
    when(certificate.getCredential()).thenReturn(credential);

    when(certificateService.findByCredentialUuid(certificateId.toString())).thenReturn(certificate);

    when(certificateService.deleteVersion(certificateId, versionId))
      .thenReturn(certificate);

    final CertificateView certificateView = subjectWithoutAcls.handleDeleteVersionRequest(certificateId.toString(), versionId.toString());

    assertEquals(versionId.toString(), certificateView.getUuid());
    assertEquals(CREDENTIAL_NAME, certificateView.getName());

    verify(permissionCheckingService, times(0)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE);
    verify(certificateService, times(1)).deleteVersion(certificateId, versionId);
  }

  @Test
  public void handleUpdateTransitionalVersion_whenUserLacksPermission_throwsException() {
    CertificateCredentialVersion credential = new CertificateCredentialVersion(CREDENTIAL_NAME);
    when(certificateService.findByCredentialUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAcls.handleUpdateTransitionalVersion(UUID_STRING, new UpdateTransitionalVersionRequest());
      fail("should throw exception");
    } catch (final PermissionException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(0)).updateTransitionalVersion(any(), any());
  }

  @Test
  public void handleUpdateTransitionalVersion_whenAclsEnabled_updatesTransitionalVersion() {
    UUID versionId = UUID.randomUUID();
    UUID certificateId = UUID.randomUUID();

    final Credential credential = mock(Credential.class);
    when(credential.getName()).thenReturn(CREDENTIAL_NAME);
    when(credential.getUuid()).thenReturn(certificateId);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);
    when(certificate.getUuid()).thenReturn(versionId);
    when(certificate.getCredential()).thenReturn(credential);

    when(certificateService.findByCredentialUuid(certificateId.toString()))
      .thenReturn(certificate);
    when(certificateService.updateTransitionalVersion(certificateId, versionId))
      .thenReturn(Collections.singletonList(certificate));

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);

    final UpdateTransitionalVersionRequest request = new UpdateTransitionalVersionRequest(versionId.toString());
    final List<CertificateView> certificateViews = subjectWithAcls.handleUpdateTransitionalVersion(certificateId.toString(), request);

    assertEquals(1, certificateViews.size());
    assertEquals(versionId.toString(), certificateViews.get(0).getUuid());
    assertEquals(CREDENTIAL_NAME, certificateViews.get(0).getName());

    verify(permissionCheckingService, times(1))
      .hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    verify(certificateService, times(1))
      .updateTransitionalVersion(certificateId, versionId);
  }

  @Test
  public void handleUpdateTransitionalVersion_whenAclsDisabled_doesntCheckPermission_andUpdatesTransitionalVersion() {
    UUID versionId = UUID.randomUUID();
    UUID certificateId = UUID.randomUUID();

    final Credential credential = mock(Credential.class);
    when(credential.getName()).thenReturn(CREDENTIAL_NAME);
    when(credential.getUuid()).thenReturn(certificateId);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);
    when(certificate.getUuid()).thenReturn(versionId);
    when(certificate.getCredential()).thenReturn(credential);

    when(certificateService.findByCredentialUuid(certificateId.toString()))
      .thenReturn(certificate);
    when(certificateService.updateTransitionalVersion(certificateId, versionId))
      .thenReturn(Collections.singletonList(certificate));

    final UpdateTransitionalVersionRequest request = new UpdateTransitionalVersionRequest(versionId.toString());
    final List<CertificateView> certificateViews = subjectWithoutAcls.handleUpdateTransitionalVersion(certificateId.toString(), request);

    assertEquals(1, certificateViews.size());
    assertEquals(versionId.toString(), certificateViews.get(0).getUuid());
    assertEquals(CREDENTIAL_NAME, certificateViews.get(0).getName());

    verify(permissionCheckingService, times(0))
      .hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    verify(certificateService, times(1))
      .updateTransitionalVersion(certificateId, versionId);
  }

  @Test
  public void handleCreateVersionsRequest_whenAclsEnabled_returnsCertificateView() {
    UUID certificateId = UUID.randomUUID();

    final CertificateCredentialValue newValue = mock(CertificateCredentialValue.class);

    final CreateVersionRequest createVersionRequest = mock(CreateVersionRequest.class);
    when(createVersionRequest.getValue()).thenReturn(newValue);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);

    final CertificateView expectedCertificateView = new CertificateView(certificate);

    when(certificateService.set(certificateId, newValue)).thenReturn(certificate);

    when(certificateService.findByCredentialUuid(certificateId.toString()))
      .thenReturn(certificate);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);

    CertificateView actualCertificateView = subjectWithAcls.handleCreateVersionsRequest(certificateId.toString(), createVersionRequest);

    assertEquals(expectedCertificateView, actualCertificateView);

    verify(permissionCheckingService, times(1))
      .hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);

    verify(certificateService, times(1))
      .set(certificateId, newValue);
  }

  @Test
  public void handleCreateVersionsRequest_whenUserLacksPermission_throwsException() {
    CertificateCredentialVersion credential = new CertificateCredentialVersion(CREDENTIAL_NAME);
    when(certificateService.findByCredentialUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAcls.handleCreateVersionsRequest(UUID_STRING, new CreateVersionRequest());
      fail("should throw exception");
    } catch (final PermissionException e) {
      assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(certificateService, times(0)).set(any(), any());
  }

  @Test
  public void handleCreateVersionsRequest_whenAclsDisabled_doesNotCheckPermissions_andReturnsCertificateView() {
    UUID certificateId = UUID.randomUUID();

    final CertificateCredentialValue newValue = mock(CertificateCredentialValue.class);

    final CreateVersionRequest createVersionRequest = mock(CreateVersionRequest.class);
    when(createVersionRequest.getValue()).thenReturn(newValue);

    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    when(certificate.getName()).thenReturn(CREDENTIAL_NAME);

    final CertificateView expectedCertificateView = new CertificateView(certificate);

    when(certificateService.set(certificateId, newValue)).thenReturn(certificate);

    when(certificateService.findByCredentialUuid(certificateId.toString()))
      .thenReturn(certificate);

    CertificateView actualCertificateView = subjectWithoutAcls
      .handleCreateVersionsRequest(certificateId.toString(), createVersionRequest);

    assertEquals(expectedCertificateView, actualCertificateView);

    verify(permissionCheckingService, times(0))
      .hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);

    verify(certificateService, times(1))
      .set(certificateId, newValue);

  }
}
