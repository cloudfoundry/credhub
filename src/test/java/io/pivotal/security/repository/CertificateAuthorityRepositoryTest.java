package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateAuthority;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.stream.Stream;

import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CertificateAuthorityRepositoryTest {

  @Autowired
  CertificateAuthorityRepository subject;

  @Test
  public void canStoreCertificateAuthoritiesOfLength7000WhichMeans7016ForGCMEncryption() throws Exception {
    final String secretName = uniquify("my-ca");
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedCertificateAuthority entity = new NamedCertificateAuthority(secretName);
    entity.setCertificate(stringBuilder.toString());
    entity.setPrivateKey(stringBuilder.toString());

    subject.save(entity);
    NamedCertificateAuthority certificateSecret = subject.findOneByName(secretName);
    assertThat(certificateSecret.getCertificate().length(), equalTo(7000));
    assertThat(certificateSecret.getPrivateKey().length(), equalTo(7000));
  }
}
