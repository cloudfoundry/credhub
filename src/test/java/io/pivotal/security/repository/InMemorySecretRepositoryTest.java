package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
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
public class InMemorySecretRepositoryTest {

  @Autowired
  InMemorySecretRepository subject;

  @Test
  @Transactional
  public void canStoreStringsOfLength7000() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedStringSecret entity = new NamedStringSecret("my-secret");
    entity.setValue(stringBuilder.toString());

    subject.save(entity);
    assertThat(((NamedStringSecret) subject.findOneByName("my-secret")).getValue().length(), equalTo(7000));
  }

  @Test
  @Transactional
  public void canStoreCertificatesOfLength7000() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedCertificateSecret entity = new NamedCertificateSecret("my-secret");
    entity.setCa(stringBuilder.toString());
    entity.setCertificate(stringBuilder.toString());
    entity.setPrivateKey(stringBuilder.toString());

    subject.save(entity);
    NamedCertificateSecret certificateSecret = (NamedCertificateSecret) subject.findOneByName("my-secret");
    assertThat(certificateSecret.getCa().length(), equalTo(7000));
    assertThat(certificateSecret.getCertificate().length(), equalTo(7000));
    assertThat(certificateSecret.getPrivateKey().length(), equalTo(7000));
  }
}