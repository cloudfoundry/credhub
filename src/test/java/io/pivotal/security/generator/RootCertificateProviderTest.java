package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500Principal;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class RootCertificateProviderTest {

  @Autowired(required = true)
  private RootCertificateProvider rootCertificateProvider;

  @Test
  public void get() throws Exception {
    X500Principal expectedPrincipal = new X500Principal("O=Organization,ST=CA,C=US");
    X509Certificate actualCert = rootCertificateProvider.get();

    assertThat(actualCert, notNullValue());
    assertThat(actualCert.getSubjectX500Principal(), reflectiveEqualTo(expectedPrincipal));
    assertThat(actualCert.getSigAlgName(), equalTo("SHA256WITHRSA"));

    long durationMillis = actualCert.getNotAfter().getTime() - actualCert.getNotBefore().getTime();
    assertThat(durationMillis, equalTo(Instant.EPOCH.plus(365, ChronoUnit.DAYS).toEpochMilli()));

    actualCert.checkValidity();
  }
}