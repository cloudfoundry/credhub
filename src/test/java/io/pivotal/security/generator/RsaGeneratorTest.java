package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import org.junit.runner.RunWith;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.security.KeyPair;
import java.security.Security;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class RsaGeneratorTest {

  @Autowired
  RsaGenerator subject;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  @MockBean
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  @MockBean
  LibcryptoRsaKeyPairGenerator keyPairGeneratorMock;

  @Autowired
  FakeKeyPairGenerator fakeKeyPairGenerator;
  private KeyPair keyPair;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());

      keyPair = fakeKeyPairGenerator.generate();
      when(keyPairGeneratorMock.generateKeyPair(anyInt())).thenReturn(keyPair);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("generateSecret", () -> {
      it("should return a generated secret", () -> {
        final RsaKey rsa = subject.generateSecret(new RsaSecretParameters());

        verify(keyPairGeneratorMock).generateKeyPair(2048);

        assertThat(rsa.getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
        assertThat(rsa.getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
      });

      it("should use the provided key length", () -> {
        RsaSecretParameters rsaSecretParameters = new RsaSecretParameters();
        rsaSecretParameters.setKeyLength(4096);

        subject.generateSecret(rsaSecretParameters);

        verify(keyPairGeneratorMock).generateKeyPair(4096);
      });
    });
  }
}
