package org.cloudfoundry.credhub.data;

import java.util.List;

import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateVersionDataServiceTest {

  private CertificateVersionDataService subject;
  private CredentialVersionRepository versionRepository;
  private CredentialFactory factory;
  private CredentialDataService dataService;

  @Before
  public void beforeEach() {
    versionRepository = mock(CredentialVersionRepository.class);
    factory = mock(CredentialFactory.class);
    dataService = mock(CredentialDataService.class);
    subject = new CertificateVersionDataService(
      versionRepository,
      factory,
      dataService
    );
  }

  @Test
  public void findActive_FindsMostRecentNonTransitionalCredentialVersion() throws Exception {
    final Credential certificate = mock(Credential.class);

    when(dataService.find("/some-ca-name")).thenReturn(certificate);
    final CredentialVersionData certificateEntity = mock(CredentialVersionData.class);
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

    final CredentialVersionData activeCert = mock(CredentialVersionData.class);
    when(versionRepository.findLatestNonTransitionalCertificateVersion(any())).thenReturn(activeCert);

    final CredentialVersionData transitionalCert = mock(CredentialVersionData.class);
    when(versionRepository.findTransitionalCertificateVersion(any())).thenReturn(transitionalCert);

    final CredentialVersion expectedActive = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(activeCert)).thenReturn(expectedActive);

    final CredentialVersion expectedTransitional = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(transitionalCert)).thenReturn(expectedTransitional);

    final List<CredentialVersion> credentialVersions = subject.findActiveWithTransitional("/some-cert-name");
    assertThat(credentialVersions, hasSize(2));
    assertThat(credentialVersions, containsInAnyOrder(expectedActive, expectedTransitional));
  }


}
