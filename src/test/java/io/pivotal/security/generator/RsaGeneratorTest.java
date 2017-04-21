package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.credential.RsaKey;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.junit.runner.RunWith;

import java.security.KeyPair;

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

      fakeKeyPairGenerator = new FakeKeyPairGenerator();
      keyPair = fakeKeyPairGenerator.generate();
      when(keyPairGenerator.generateKeyPair(anyInt())).thenReturn(keyPair);

      subject = new RsaGenerator(keyPairGenerator);
    });

    describe("generateCredential", () -> {
      it("should return a generated credential", () -> {
        final RsaKey rsa = subject.generateCredential(new RsaGenerationParameters());

        verify(keyPairGenerator).generateKeyPair(2048);

        assertThat(rsa.getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
        assertThat(rsa.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        RsaGenerationParameters rsaGenerationParameters = new RsaGenerationParameters();
        rsaGenerationParameters.setKeyLength(4096);

        subject.generateCredential(rsaGenerationParameters);

        verify(keyPairGenerator).generateKeyPair(4096);
      });
    });
  }
}
