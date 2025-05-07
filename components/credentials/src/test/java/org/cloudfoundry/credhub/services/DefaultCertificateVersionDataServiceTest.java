package org.cloudfoundry.credhub.services;

import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class DefaultCertificateVersionDataServiceTest {

  private DefaultCertificateVersionDataService subject;
  private CredentialVersionRepository versionRepository;
  private CredentialFactory factory;
  private CredentialDataService dataService;

  @BeforeAll
  public static void setUpAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @BeforeEach
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    versionRepository = mock(CredentialVersionRepository.class);
    factory = mock(CredentialFactory.class);
    dataService = mock(CredentialDataService.class);
    subject = new DefaultCertificateVersionDataService(
      versionRepository,
      factory,
      dataService
    );
  }

  @Test
  public void findByCredentialUUID_ReturnsLatestNonTransitionalVersion_WhenThereAreTransitionalAndNonTransitionalVersions() {
    final UUID uuid = UUID.randomUUID();
    final String uuidString = uuid.toString();
    final CertificateCredentialVersionData certificateEntity = mock(CertificateCredentialVersionData.class);
    final CertificateCredentialVersion certificateCredentialVersion = mock(CertificateCredentialVersion.class);

    when(versionRepository.findLatestNonTransitionalCertificateVersion(uuid)).thenReturn(certificateEntity);
    when(factory.makeCredentialFromEntity(certificateEntity)).thenReturn(certificateCredentialVersion);

    assertThat(subject.findByCredentialUUID(uuidString), equalTo(certificateCredentialVersion));
    verify(versionRepository, times(1)).findLatestNonTransitionalCertificateVersion(uuid);
    verify(versionRepository, never()).findTransitionalCertificateVersion(uuid);
    verify(factory, times(1)).makeCredentialFromEntity(certificateEntity);
  }

  @Test
  public void findByCredentialUUID_ReturnsLatestTransitionalVersion_WhenThereAreOnlyTransitionalVersions() {
    final UUID uuid = UUID.randomUUID();
    final String uuidString = uuid.toString();
    final CertificateCredentialVersionData certificateEntity = mock(CertificateCredentialVersionData.class);
    final CertificateCredentialVersion certificateCredentialVersion = mock(CertificateCredentialVersion.class);

    when(versionRepository.findLatestNonTransitionalCertificateVersion(uuid)).thenReturn(null);
    when(versionRepository.findTransitionalCertificateVersion(uuid)).thenReturn(certificateEntity);
    when(factory.makeCredentialFromEntity(certificateEntity)).thenReturn(certificateCredentialVersion);

    assertThat(subject.findByCredentialUUID(uuidString), equalTo(certificateCredentialVersion));
    verify(versionRepository, times(1)).findLatestNonTransitionalCertificateVersion(uuid);
    verify(versionRepository, times(1)).findTransitionalCertificateVersion(uuid);
    verify(factory, times(1)).makeCredentialFromEntity(certificateEntity);
  }

  @Test
  public void findActive_FindsMostRecentNonTransitionalCredentialVersion() throws Exception {
    final Credential certificate = mock(Credential.class);

    when(dataService.find("/some-ca-name")).thenReturn(certificate);
    final CertificateCredentialVersionData certificateEntity = mock(CertificateCredentialVersionData.class);
    when(versionRepository.findLatestNonTransitionalCertificateVersion(any())).thenReturn(certificateEntity);

    final CredentialVersion expectedVersion = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(certificateEntity)).thenReturn(expectedVersion);

    final CredentialVersion activeVersion = subject.findActive("/some-ca-name");
    assertThat(activeVersion, equalTo(expectedVersion));
  }


  @Test
  public void findActiveWithTransitional_findsMostRecentNonTransitionalAndTransitionalCredentialVersions() throws Exception {
    final Credential certificate = mock(Credential.class);

    when(dataService.find("/some-cert-name")).thenReturn(certificate);

    final CertificateCredentialVersionData activeCert = mock(CertificateCredentialVersionData.class);
    when(versionRepository.findLatestNonTransitionalCertificateVersion(any())).thenReturn(activeCert);

    final CertificateCredentialVersionData transitionalCert = mock(CertificateCredentialVersionData.class);
    when(versionRepository.findTransitionalCertificateVersion(any())).thenReturn(transitionalCert);

    final CredentialVersion expectedActive = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(activeCert)).thenReturn(expectedActive);

    final CredentialVersion expectedTransitional = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(transitionalCert)).thenReturn(expectedTransitional);

    final List<CredentialVersion> credentialVersions = subject.findBothActiveCertAndTransitionalCert("/some-cert-name");
    assertThat(credentialVersions, hasSize(2));
    assertThat(credentialVersions, containsInAnyOrder(expectedActive, expectedTransitional));
  }

  @Test
  public void findAllValidVersions_findsAllVersionThatWithCorrectlyFormattedCerts() throws Exception {
    UUID uuid = UUID.randomUUID();

    final CertificateCredentialVersionData goodCert0 = mock(CertificateCredentialVersionData.class);
    when(goodCert0.getCertificate()).thenReturn(TestConstants.TEST_CERTIFICATE);

    final CertificateCredentialVersionData goodCert1 = mock(CertificateCredentialVersionData.class);
    when(goodCert1.getCertificate()).thenReturn(TestConstants.TEST_CERTIFICATE);

    final CertificateCredentialVersionData badCert = mock(CertificateCredentialVersionData.class);
    when(badCert.getCertificate()).thenReturn("some bad cert");

    List<CredentialVersionData<?>> certs = Arrays.asList(goodCert0, goodCert1, badCert);
    when(versionRepository.findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(eq(uuid), any())).thenReturn(certs);

    ArgumentCaptor<List<CredentialVersionData<?>>> validCertsArgument = ArgumentCaptor.forClass(List.class);

    List<CredentialVersion> validCredentialVersions = mock(List.class);
    when(factory.makeCredentialsFromEntities(any())).thenReturn(validCredentialVersions);


    final List<CredentialVersion> credentialVersions = subject.findAllValidVersions(uuid);
    assertThat(credentialVersions, equalTo(validCredentialVersions));

    verify(factory).makeCredentialsFromEntities(validCertsArgument.capture());

    assertThat(validCertsArgument.getValue().size(), equalTo(2));
  }

}
