package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500Principal;
import javax.validation.ValidationException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class RootCertificateProviderTest {

  @Autowired(required = true)
  private RootCertificateProvider rootCertificateProvider;
  private static KeyPair keyPair;

  @BeforeClass
  public static void setupClass() throws NoSuchProviderException, NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    keyPair = generateKeyPair();
  }

  @Test
  public void getSucceeds() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.setOrganizationUnit("My Unit");
    inputParameters.setLocality("My Locality");
    inputParameters.setCommonName("My Common Name");

    X500Principal expectedPrincipal = new X500Principal("O=my-org,ST=NY,C=USA,CN=My Common Name,OU=My Unit,L=My Locality");
    X509Certificate actualCert = rootCertificateProvider.get(keyPair, inputParameters);

    actualCert.checkValidity();
    assertThat(actualCert, notNullValue());
    assertThat(actualCert.getSubjectX500Principal(), BeanMatchers.theSameAs(expectedPrincipal));
    assertThat(actualCert.getSigAlgName(), equalTo("SHA256WITHRSA"));

    long durationMillis = actualCert.getNotAfter().getTime() - actualCert.getNotBefore().getTime();
    assertThat(durationMillis, equalTo(Instant.EPOCH.plus(365, ChronoUnit.DAYS).toEpochMilli()));
  }

  @Test
  public void canGenerateCertificateWithAlternateNames() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("1.1.1.1");
//    inputParameters.addAlternateName("2.2.2.0/24");  // spec indicates that bitmask is legal
    inputParameters.addAlternativeName("example.com");
    inputParameters.addAlternativeName("foo.pivotal.io");
    inputParameters.addAlternativeName("*.pivotal.io");

    X509Certificate actualCert = rootCertificateProvider.get(keyPair, inputParameters);

    actualCert.checkValidity();
    Collection<List<?>> subjectAlternativeNames = actualCert.getSubjectAlternativeNames();
    ArrayList<String> alternateNames = subjectAlternativeNames.stream().map(generalName ->
        generalName.get(1).toString()).collect(Collectors.toCollection(ArrayList::new));

    assertThat(alternateNames, containsInAnyOrder(
        "1.1.1.1",
        "example.com",
        "foo.pivotal.io",
        "*.pivotal.io"
        // "2.2.2.0/24"
    ));
  }

  @Test
  public void zeroAlternateNamesYieldsEmptyArrayOfNames() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();

    X509Certificate actualCert = rootCertificateProvider.get(keyPair, inputParameters);

    actualCert.checkValidity();
    assertThat(actualCert.getSubjectAlternativeNames(), nullValue());
  }

  @Test(expected = ValidationException.class)
  public void alternativeNamesInvalidatesSpecialCharsDns() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("foo!@#$%^&*()_-+=.com");

    rootCertificateProvider.get(keyPair, inputParameters);
  }

  @Test(expected = ValidationException.class)
  public void alternativeNamesInvalidatesSpaceInDns() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("foo pivotal.io");

    rootCertificateProvider.get(keyPair, inputParameters);
  }

  @Test(expected = ValidationException.class)
  public void alternativeNamesInvalidateBadIpAddresses() throws Exception {
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("1.2.3.999");

    rootCertificateProvider.get(keyPair, inputParameters);
  }

  @Test(expected = ValidationException.class)
  public void alternativeNamesInvalidateEmailAddresses() throws Exception {
    // email addresses are allowed in certificate spec, but we do not allow them per PM requirements
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("x@y.com");

    rootCertificateProvider.get(keyPair, inputParameters);
  }

  @Test(expected = ValidationException.class)
  public void alternativeNamesInvalidateUrls() throws Exception {
    // URLs are allowed in certificate spec, but we do not allow them per PM requirements
    CertificateSecretParameters inputParameters = getMinimumCertificateSecretParameters();
    inputParameters.addAlternativeName("https://foo.com");

    rootCertificateProvider.get(keyPair, inputParameters);
  }

  private CertificateSecretParameters getMinimumCertificateSecretParameters() {
    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    inputParameters.setOrganization("my-org");
    inputParameters.setState("NY");
    inputParameters.setCountry("USA");
    return inputParameters;
  }

  private static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(1024); // for testing only; strength not important
    return generator.generateKeyPair();
  }
}