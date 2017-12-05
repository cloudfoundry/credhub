package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
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
    Credential certificate = mock(Credential.class);

    when(dataService.find("/some-ca-name")).thenReturn(certificate);
    CredentialVersionData certificateEntity = mock(CredentialVersionData.class);
    when(versionRepository.findLatestNonTransitionalCertificateVersion(any())).thenReturn(certificateEntity);

    CredentialVersion expectedVersion = mock(CredentialVersion.class);
    when(factory.makeCredentialFromEntity(certificateEntity)).thenReturn(expectedVersion);

    CredentialVersion activeVersion = subject.findActive("/some-ca-name");
    assertThat(activeVersion, equalTo(expectedVersion));
  }

}
