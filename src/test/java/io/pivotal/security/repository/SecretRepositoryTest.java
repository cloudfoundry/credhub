package io.pivotal.security.repository;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.stream.Stream;

import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class SecretRepositoryTest {

  @Autowired
  SecretRepository subject;

  private String secretName = uniquify("my-secret");

  @Test
  public void canStoreStringsOfLength7000WhichMeans7016ForGCM() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedStringSecret entity = new NamedStringSecret(secretName);
    entity.setValue(stringBuilder.toString());

    subject.save(entity);
    assertThat(((NamedStringSecret) subject.findOneByName(secretName)).getValue().length(), equalTo(7000));
  }

  @Test
  public void canStoreCertificatesOfLength7000WhichMeans7016ForGCM() throws Exception {
    final StringBuilder stringBuilder = new StringBuilder(7000);
    Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
    NamedCertificateSecret entity = new NamedCertificateSecret(secretName);
    entity.setRoot(stringBuilder.toString());
    entity.setCertificate(stringBuilder.toString());
    entity.setPrivateKey(stringBuilder.toString());

    subject.save(entity);
    NamedCertificateSecret certificateSecret = (NamedCertificateSecret) subject.findOneByName(secretName);
    assertThat(certificateSecret.getRoot().length(), equalTo(7000));
    assertThat(certificateSecret.getCertificate().length(), equalTo(7000));
    assertThat(certificateSecret.getPrivateKey().length(), equalTo(7000));
  }
}