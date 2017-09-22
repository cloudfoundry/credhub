package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SshGeneratorTest {

  private SshGenerator subject;
  private LibcryptoRsaKeyPairGenerator keyPairGeneratorMock;

  private KeyPair keyPair;

  private UserContext userContext;

  {
    beforeEach(() -> {
      keyPairGeneratorMock = mock(LibcryptoRsaKeyPairGenerator.class);
      userContext = null;
      subject = new SshGenerator(keyPairGeneratorMock);

      keyPair = new FakeKeyPairGenerator().generate();
      when(keyPairGeneratorMock.generateKeyPair(anyInt())).thenReturn(keyPair);
    });

    describe("generateCredential", () -> {
      it("should return a generated credential", () -> {
        final SshCredentialValue ssh = subject.generateCredential(new SshGenerationParameters(), userContext);

        verify(keyPairGeneratorMock).generateKeyPair(2048);

        assertThat(ssh.getPublicKey(),
            equalTo(CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())));
        assertThat(ssh.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        SshGenerationParameters sshGenerationParameters = new SshGenerationParameters();
        sshGenerationParameters.setKeyLength(4096);

        subject.generateCredential(sshGenerationParameters, userContext);

        verify(keyPairGeneratorMock).generateKeyPair(4096);
      });

      it("should use the provided ssh comment", () -> {
        SshGenerationParameters sshGenerationParameters = new SshGenerationParameters();
        sshGenerationParameters.setSshComment("this is an ssh comment");

        final SshCredentialValue ssh = subject.generateCredential(sshGenerationParameters, userContext);

        String expectedPublicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())
            + " this is an ssh comment";

        assertThat(ssh.getPublicKey(), equalTo(expectedPublicKey));
      });
    });
  }
}
