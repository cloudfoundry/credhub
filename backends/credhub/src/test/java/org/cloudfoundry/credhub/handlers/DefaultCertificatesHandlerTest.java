package org.cloudfoundry.credhub.handlers;

import java.security.Security;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
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
import org.cloudfoundry.credhub.utils.TestConstants;
import org.cloudfoundry.credhub.views.CertificateCredentialView;
import org.cloudfoundry.credhub.views.CertificateCredentialsView;
import org.cloudfoundry.credhub.views.CertificateView;
import org.junit.Before;
import org.junit.Test;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
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
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

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
  public void handleGetAllRequest_returnsCertificateCredentialsView() {
    final Credential certWithCaAndChildren = mock(Credential.class);
    final UUID certWithCaAndChildrenUuid = UUID.randomUUID();
    final String certWithCaAndChildrenName = "certWithCaAndChildren";
    final String certWithCaAndChildrenCaName = "/testCaA";
    final List<String> childCertNames = asList("childCert1", "childCert2");
    when(certWithCaAndChildren.getUuid()).thenReturn(certWithCaAndChildrenUuid);
    when(certWithCaAndChildren.getName()).thenReturn(certWithCaAndChildrenName);

    final Credential selfSignedCert = mock(Credential.class);
    final UUID selfSignedCertUuid = UUID.randomUUID();
    final String selfSignedCertName = "selfSignedCert";
    when(selfSignedCert.getUuid()).thenReturn(selfSignedCertUuid);
    when(selfSignedCert.getName()).thenReturn(selfSignedCertName);

    final UUID certificateWithNoValidVersionsUuid = UUID.randomUUID();
    final Credential certificateWithNoValidVersions = mock(Credential.class);
    when(certificateWithNoValidVersions.getUuid()).thenReturn(certificateWithNoValidVersionsUuid);

    when(permissionedCertificateService.getAll())
      .thenReturn(asList(certWithCaAndChildren, selfSignedCert, certificateWithNoValidVersions));

    final CertificateCredentialVersion certWithCaAndChildrenVersion = new CertificateCredentialVersion(certWithCaAndChildrenName);
    certWithCaAndChildrenVersion.setUuid(UUID.randomUUID());
    certWithCaAndChildrenVersion.setExpiryDate(Instant.now());
    certWithCaAndChildrenVersion.setCaName(certWithCaAndChildrenCaName);
    certWithCaAndChildrenVersion.setCertificate(TestConstants.TEST_CERTIFICATE);

    final CertificateCredentialVersion selfSignedCertVersion = new CertificateCredentialVersion(selfSignedCertName);
    selfSignedCertVersion.setUuid(UUID.randomUUID());
    selfSignedCertVersion.setExpiryDate(Instant.now());
    selfSignedCertVersion.setCertificate(TestConstants.TEST_CA);

    when(permissionedCertificateService.getAllValidVersions(certWithCaAndChildrenUuid))
      .thenReturn(asList(certWithCaAndChildrenVersion));
    when(permissionedCertificateService.findSignedCertificates(certWithCaAndChildrenName))
      .thenReturn(childCertNames);

    when(permissionedCertificateService.getAllValidVersions(selfSignedCertUuid))
      .thenReturn(asList(selfSignedCertVersion));
    when(permissionedCertificateService.findSignedCertificates(selfSignedCertName))
      .thenReturn(emptyList());

    when(permissionedCertificateService.getAllValidVersions(certificateWithNoValidVersionsUuid))
      .thenReturn(emptyList());

    final CertificateCredentialsView certificateCredentialsView = subject.handleGetAllRequest();

    assertThat(certificateCredentialsView.getCertificates().size(), equalTo(3));

    final CertificateCredentialView actualCertWithCa = certificateCredentialsView.getCertificates().get(0);
    assertThat(actualCertWithCa.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualCertWithCa.getSignedBy(), equalTo(certWithCaAndChildrenCaName));

    final CertificateCredentialView actualSelfSignedCert = certificateCredentialsView.getCertificates().get(1);
    assertThat(actualSelfSignedCert.getCertificateVersionViews().size(), equalTo(1));
    assertThat(actualSelfSignedCert.getSignedBy(), equalTo(selfSignedCertName));

    final CertificateCredentialView actualCertificateWithNoValidVersions = certificateCredentialsView.getCertificates().get(2);
    assertThat(actualCertificateWithNoValidVersions.getCertificateVersionViews().size(), equalTo(0));
    assertThat(actualCertificateWithNoValidVersions.getSignedBy(), equalTo(""));
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

    when(permissionedCertificateService.getByName(certificateName))
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

    when(permissionedCertificateService.getAllValidVersions(uuid))
      .thenReturn(asList(nonTransitionalVersion, transitionalVersion));
    when(permissionedCertificateService.findSignedCertificates(certificateName))
      .thenReturn(childCertNames);

    final CertificateCredentialsView certificateCredentialsView = subject.handleGetByNameRequest(certificateName);

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

    final CredentialVersion credentialVersion = new CertificateCredentialVersion(certificateName);
    when(permissionedCertificateService.getVersions(uuid, false))
      .thenReturn(Collections.singletonList(credentialVersion));
    final List<CertificateView> certificateViews = subject
      .handleGetAllVersionsRequest(uuid.toString(), false);

    assertThat(certificateViews.size(), equalTo(1));
    assertThat(certificateViews.get(0).getName(), equalTo(certificateName));
  }
}
