package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateAuthority;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.util.stream.Stream;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemoryAuthorityRepositoryTest {

  @Autowired
  InMemoryAuthorityRepository subject;

  @Test
  @Transactional
  public void canStoreCertificateAuthoritiesOfLength7000() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedCertificateAuthority entity = new NamedCertificateAuthority("my-ca");
    entity.setPub(stringBuilder.toString());
    entity.setPriv(stringBuilder.toString());

    subject.save(entity);
    NamedCertificateAuthority certificateSecret = (NamedCertificateAuthority) subject.findOneByName("my-ca");
    assertThat(certificateSecret.getPub().length(), equalTo(7000));
    assertThat(certificateSecret.getPriv().length(), equalTo(7000));
  }
}