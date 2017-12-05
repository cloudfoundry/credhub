package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.request.RsaGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateFormatter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyPair;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RsaGeneratorTest {

  private LibcryptoRsaKeyPairGenerator keyPairGenerator;
  private RsaGenerator subject;
  private FakeKeyPairGenerator fakeKeyPairGenerator;

  private KeyPair keyPair;

  @Before
  public void beforeEach() throws Exception {
    keyPairGenerator = mock(LibcryptoRsaKeyPairGenerator.class);
    fakeKeyPairGenerator = new FakeKeyPairGenerator();
    keyPair = fakeKeyPairGenerator.generate();
    when(keyPairGenerator.generateKeyPair(anyInt())).thenReturn(keyPair);

    subject = new RsaGenerator(keyPairGenerator);
  }

  @Test
  public void generateCredential_shouldReturnAGeneratedCredential() throws Exception {
    final RsaCredentialValue rsa = subject.generateCredential(new RsaGenerationParameters());

    verify(keyPairGenerator).generateKeyPair(2048);

    assertThat(rsa.getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
    assertThat(rsa.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
  }

  @Test
  public void generateCredential_shouldUseTheProvidedKeyLength() throws Exception {
    RsaGenerationParameters rsaGenerationParameters = new RsaGenerationParameters();
    rsaGenerationParameters.setKeyLength(4096);

    subject.generateCredential(rsaGenerationParameters);

    verify(keyPairGenerator).generateKeyPair(4096);
  }
}
