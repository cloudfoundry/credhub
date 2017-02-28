package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.util.CertificateFormatter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

@RunWith(Spectrum.class)
public class SshGeneratorTest {

  private SshGenerator subject;
  private LibcryptoRsaKeyPairGenerator keyPairGeneratorMock;

  private KeyPair keyPair;

  {
    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());
      keyPairGeneratorMock = mock(LibcryptoRsaKeyPairGenerator.class);
      subject = new SshGenerator(keyPairGeneratorMock);

      keyPair = new FakeKeyPairGenerator().generate();
      when(keyPairGeneratorMock.generateKeyPair(anyInt())).thenReturn(keyPair);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("generateSecret", () -> {
      it("should return a generated secret", () -> {
        final SshKey ssh = subject.generateSecret(new SshSecretParameters());

        verify(keyPairGeneratorMock).generateKeyPair(2048);

        assertThat(ssh.getPublicKey(), equalTo(CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())));
        assertThat(ssh.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        SshSecretParameters sshSecretParameters = new SshSecretParameters();
        sshSecretParameters.setKeyLength(4096);

        subject.generateSecret(sshSecretParameters);

        verify(keyPairGeneratorMock).generateKeyPair(4096);
      });

      it("should use the provided ssh comment", () -> {
        SshSecretParameters sshSecretParameters = new SshSecretParameters();
        sshSecretParameters.setSshComment("this is an ssh comment");

        final SshKey ssh = subject.generateSecret(sshSecretParameters);

        String expectedPublicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + " this is an ssh comment";

        assertThat(ssh.getPublicKey(), equalTo(expectedPublicKey));
      });
    });
  }
}
