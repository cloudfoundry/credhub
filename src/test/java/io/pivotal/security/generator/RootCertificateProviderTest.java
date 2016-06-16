package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.CertificateSecretParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class RootCertificateProviderTest {

  @Autowired(required = true)
  private RootCertificateProvider rootCertificateProvider;

  @Test
  public void getSucceeds() throws Exception {
    KeyPair keyPair = generateKeyPair();
    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    inputParameters.setCommonName("My Common Name");
    inputParameters.setOrganization("organization.io");
    inputParameters.setOrganizationUnit("My Unit");
    inputParameters.setLocality("My Locality");
    inputParameters.setState("My State");
    inputParameters.setCountry("My Country");

    X500Principal expectedPrincipal = new X500Principal("O=organization.io,ST=My State,C=My Country,CN=My Common Name,OU=My Unit,L=My Locality");
    X509Certificate actualCert = rootCertificateProvider.get(keyPair, inputParameters);

    assertThat(actualCert, notNullValue());
    assertThat(actualCert.getSubjectX500Principal(), reflectiveEqualTo(expectedPrincipal));
    assertThat(actualCert.getSigAlgName(), equalTo("SHA256WITHRSA"));

    long durationMillis = actualCert.getNotAfter().getTime() - actualCert.getNotBefore().getTime();
    assertThat(durationMillis, equalTo(Instant.EPOCH.plus(365, ChronoUnit.DAYS).toEpochMilli()));

    actualCert.checkValidity();
  }

  private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(1024);
    return generator.generateKeyPair();
  }
}