package io.pivotal.security.generator;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.CertificateFormatter;
import java.security.KeyPair;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class RsaGeneratorTest {

  private LibcryptoRsaKeyPairGenerator keyPairGenerator;
  private RsaGenerator subject;
  private FakeKeyPairGenerator fakeKeyPairGenerator;

  private KeyPair keyPair;

  {
    beforeEach(() -> {
      keyPairGenerator = mock(LibcryptoRsaKeyPairGenerator.class);

      fakeKeyPairGenerator = new FakeKeyPairGenerator();
      keyPair = fakeKeyPairGenerator.generate();
      when(keyPairGenerator.generateKeyPair(anyInt())).thenReturn(keyPair);

      subject = new RsaGenerator(keyPairGenerator);
    });

    describe("generateSecret", () -> {
      it("should return a generated secret", () -> {
        final RsaKey rsa = subject.generateSecret(new RsaGenerationParameters());

        verify(keyPairGenerator).generateKeyPair(2048);

        assertThat(rsa.getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
        assertThat(rsa.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        RsaGenerationParameters rsaSecretParameters = new RsaGenerationParameters();
        rsaSecretParameters.setKeyLength(4096);

        subject.generateSecret(rsaSecretParameters);

        verify(keyPairGenerator).generateKeyPair(4096);
      });
    });
  }
}
