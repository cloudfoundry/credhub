package org.cloudfoundry.credhub.handlers;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.certificates.CertificateService;
import org.cloudfoundry.credhub.certificates.DefaultCertificatesHandler;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator;
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator;
import org.cloudfoundry.credhub.permissions.PermissionedCertificateService;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.views.CertificateCredentialView;
import org.cloudfoundry.credhub.views.CertificateCredentialsView;
import org.cloudfoundry.credhub.views.CertificateView;
import org.junit.Before;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCertificatesHandlerTest {

  private static final String UUID_STRING = "fake-uuid";

  private DefaultCertificatesHandler subject;
  private CertificateService certificateService;
  private UniversalCredentialGenerator universalCredentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private PermissionedCertificateService permissionedCertificateService;

  @Before
  public void beforeEach() {
    permissionedCertificateService = mock(PermissionedCertificateService.class);
    certificateService = mock(CertificateService.class);
    universalCredentialGenerator = mock(UniversalCredentialGenerator.class);
    generationRequestGenerator = mock(GenerationRequestGenerator.class);
    subject = new DefaultCertificatesHandler(
      permissionedCertificateService,
      certificateService,
      universalCredentialGenerator,
      generationRequestGenerator,
      new CEFAuditRecord()
    );
  }

  @Test
  public void handleGetAllRequest_returnsCertificateCredentialsView() {
    final UUID uuidA = UUID.randomUUID();
    final Credential credentialA = mock(Credential.class);
    when(credentialA.getUuid()).thenReturn(uuidA);
    when(credentialA.getName()).thenReturn("credentialA");

    final UUID uuidB = UUID.randomUUID();
    final Credential credentialB = mock(Credential.class);
    when(credentialB.getUuid()).thenReturn(uuidB);
    when(credentialB.getName()).thenReturn("credentialB");

    when(permissionedCertificateService.getAll())
      .thenReturn(asList(credentialA, credentialB));

    final CertificateCredentialVersion versionA = new CertificateCredentialVersion("credentialA");
    versionA.setUuid(UUID.randomUUID());
    versionA.setExpiryDate(Instant.now());
    versionA.setTransitional(false);

    final CertificateCredentialVersion versionB = new CertificateCredentialVersion("credentialB");
    versionB.setUuid(UUID.randomUUID());
    versionB.setExpiryDate(Instant.now());
    versionB.setTransitional(false);

    when(permissionedCertificateService.getVersions(uuidA, false))
      .thenReturn(asList(versionA));

    when(permissionedCertificateService.getVersions(uuidB, false))
      .thenReturn(asList(versionB));

    final CertificateCredentialsView certificateCredentialsView = subject.handleGetAllRequest();

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(2));

    final CertificateCredentialView certificateA = certificateCredentialsView.getCertificates().get(0);
    assertThat(certificateA.getCertificateVersionViews().size(), equalTo(1));

    final CertificateCredentialView certificateB = certificateCredentialsView.getCertificates().get(1);
    assertThat(certificateB.getCertificateVersionViews().size(), equalTo(1));
  }

  @Test
  public void handleRegenerate_passesOnTransitionalFlagWhenRegeneratingCertificate() {
    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    final CertificateCredentialVersion certificate = mock(CertificateCredentialVersion.class);
    final CertificateCredentialValue newValue = mock(CertificateCredentialValue.class);

    when(certificate.getName()).thenReturn("test");

    when(certificateService.findByCredentialUuid(eq(UUID_STRING))).thenReturn(certificate);
    when(generationRequestGenerator.createGenerateRequest(eq(certificate)))
      .thenReturn(generateRequest);
    when(universalCredentialGenerator.generate(eq(generateRequest))).thenReturn(newValue);
    when(permissionedCertificateService.save(eq(certificate), any(), any()))
      .thenReturn(mock(CertificateCredentialVersion.class));

    final CertificateRegenerateRequest regenerateRequest = new CertificateRegenerateRequest(true);

    subject.handleRegenerate(UUID_STRING, regenerateRequest);

    verify(newValue).setTransitional(true);
  }

  @Test
  public void handleGetByNameRequest_returnsCertificateCredentialsViews() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some certificate";

    final Credential credential = mock(Credential.class);
    when(credential.getUuid()).thenReturn(uuid);

    when(permissionedCertificateService.getByName(certificateName))
      .thenReturn(Collections.singletonList(credential));

    final CertificateCredentialVersion nonTransitionalVersion = new CertificateCredentialVersion(certificateName);
    nonTransitionalVersion.setUuid(UUID.randomUUID());
    nonTransitionalVersion.setExpiryDate(Instant.now());
    nonTransitionalVersion.setTransitional(false);
    final CertificateCredentialVersion transitionalVersion = new CertificateCredentialVersion(certificateName);
    transitionalVersion.setUuid(UUID.randomUUID());
    transitionalVersion.setExpiryDate(Instant.now());
    transitionalVersion.setTransitional(true);

    when(permissionedCertificateService.getVersions(uuid, false))
      .thenReturn(asList(nonTransitionalVersion, transitionalVersion));

    final CertificateCredentialsView certificateCredentialsView = subject.handleGetByNameRequest(certificateName);

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(1));

    final CertificateCredentialView certificate = certificateCredentialsView.getCertificates().get(0);
    assertThat(certificate.getCertificateVersionViews().size(), equalTo(2));
  }

  @Test
  public void handleGetAllVersionsRequest_returnsListOfCertificateViews() {
    final UUID uuid = UUID.randomUUID();
    final String certificateName = "some certificate";

    final CredentialVersion credentialVersion = new CertificateCredentialVersion(certificateName);
    when(permissionedCertificateService.getVersions(uuid, false))
      .thenReturn(Collections.singletonList(credentialVersion));
    final List<CertificateView> certificateViews = subject
      .handleGetAllVersionsRequest(uuid.toString(), false);

    assertThat(certificateViews.size(), equalTo(1));
    assertThat(certificateViews.get(0).getName(), equalTo(certificateName));
  }
}
