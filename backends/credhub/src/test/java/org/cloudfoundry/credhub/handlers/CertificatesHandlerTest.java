package org.cloudfoundry.credhub.handlers;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.certificates.CertificateService;
import org.cloudfoundry.credhub.certificates.DefaultCertificatesHandler;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator;
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator;
import org.cloudfoundry.credhub.permissions.PermissionedCertificateService;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateRegenerateRequest;
import org.cloudfoundry.credhub.views.CertificateView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class
CertificatesHandlerTest {

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
