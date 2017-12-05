package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.request.SshGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateFormatter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SshGeneratorTest {

  private SshGenerator subject;
  private LibcryptoRsaKeyPairGenerator keyPairGeneratorMock;

  private KeyPair keyPair;

  private UserContext userContext;

  @Before
  public void beforeEach() throws Exception {
    keyPairGeneratorMock = mock(LibcryptoRsaKeyPairGenerator.class);
    userContext = null;
    subject = new SshGenerator(keyPairGeneratorMock);

    keyPair = new FakeKeyPairGenerator().generate();
    when(keyPairGeneratorMock.generateKeyPair(anyInt())).thenReturn(keyPair);
  }

  @Test
  public void generateCredential_shouldReturnAGeneratedCredential() throws Exception {
    final SshCredentialValue ssh = subject.generateCredential(new SshGenerationParameters());

    verify(keyPairGeneratorMock).generateKeyPair(2048);

    assertThat(ssh.getPublicKey(),
        equalTo(CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())));
    assertThat(ssh.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
  }

  @Test
  public void generateCredential_shouldUseTheProvidedKeyLength() throws Exception {
    SshGenerationParameters sshGenerationParameters = new SshGenerationParameters();
    sshGenerationParameters.setKeyLength(4096);

    subject.generateCredential(sshGenerationParameters);

    verify(keyPairGeneratorMock).generateKeyPair(4096);
  }

  @Test
  public void generateCredential_shouldUseTheProvidedSSHComment() throws Exception {
    SshGenerationParameters sshGenerationParameters = new SshGenerationParameters();
    sshGenerationParameters.setSshComment("this is an ssh comment");

    final SshCredentialValue ssh = subject.generateCredential(sshGenerationParameters);

    String expectedPublicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())
        + " this is an ssh comment";

    assertThat(ssh.getPublicKey(), equalTo(expectedPublicKey));
  }
}
