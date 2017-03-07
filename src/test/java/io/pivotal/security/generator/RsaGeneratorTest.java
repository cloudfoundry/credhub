package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.CertificateFormatter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.Security;

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

@RunWith(Spectrum.class)
public class RsaGeneratorTest {
  private LibcryptoRsaKeyPairGenerator keyPairGenerator;
  private RsaGenerator subject;
  private FakeKeyPairGenerator fakeKeyPairGenerator;

  private KeyPair keyPair;

  {
    beforeEach(() -> {
      keyPairGenerator = mock(LibcryptoRsaKeyPairGenerator.class);

      Security.addProvider(new BouncyCastleProvider());

      fakeKeyPairGenerator = new FakeKeyPairGenerator();
      keyPair = fakeKeyPairGenerator.generate();
      when(keyPairGenerator.generateKeyPair(anyInt())).thenReturn(keyPair);

      subject = new RsaGenerator(keyPairGenerator);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("generateSecret", () -> {
      it("should return a generated secret", () -> {
        final RsaKey rsa = subject.generateSecret(new RsaSecretParameters());

        verify(keyPairGenerator).generateKeyPair(2048);

        assertThat(rsa.getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
        assertThat(rsa.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        RsaSecretParameters rsaSecretParameters = new RsaSecretParameters();
        rsaSecretParameters.setKeyLength(4096);

        subject.generateSecret(rsaSecretParameters);

        verify(keyPairGenerator).generateKeyPair(4096);
      });
    });
  }
}
