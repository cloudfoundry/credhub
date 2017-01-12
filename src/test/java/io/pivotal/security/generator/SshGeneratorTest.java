package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.SshSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.SshView;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SshGeneratorTest {

  @Autowired
  SshGenerator subject;

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
    wireAndUnwire(this, false);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());

      keyPair = fakeKeyPairGenerator.generate();
      when(keyPairGeneratorMock.generateKeyPair(anyInt())).thenReturn(keyPair);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("generateSecret", () -> {
      it("should return a generated secret", () -> {
        final SshView ssh = subject.generateSecret(new SshSecretParameters());

        verify(keyPairGeneratorMock).generateKeyPair(2048);

        assertThat(ssh.getSshBody().getPublicKey(), equalTo(CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic())));
        assertThat(ssh.getSshBody().getPrivateKey(), equalTo(CertificateFormatter.pemOf(keyPair.getPrivate())));
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

        final SshView ssh = subject.generateSecret(sshSecretParameters);

        String expectedPublicKey = CertificateFormatter.derOf((RSAPublicKey) keyPair.getPublic()) + " this is an ssh comment";

        assertThat(ssh.getSshBody().getPublicKey(), equalTo(expectedPublicKey));
      });
    });
  }
}
