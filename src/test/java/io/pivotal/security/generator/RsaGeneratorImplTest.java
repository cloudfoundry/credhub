package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.RsaSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.RsaSecret;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.security.KeyPair;
import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class RsaGeneratorImplTest {
  @InjectMocks
  @Autowired
  RsaGeneratorImpl subject;

  @Mock
  DateTimeProvider dateTimeProvider;

  @Mock
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  @Mock
  RsaKeyPairGenerator keyPairGeneratorMock;

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
        final RsaSecret rsa = subject.generateSecret(new RsaSecretParameters());

        verify(keyPairGeneratorMock).generateKeyPair(2048);

        assertThat(rsa.getRsaBody().getPublicKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPublic())));
        assertThat(rsa.getRsaBody().getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
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
