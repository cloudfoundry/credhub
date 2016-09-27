package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionService;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import java.util.Arrays;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedCertificateSecretTest {

  @Autowired
  SecretRepository repository;

  @Autowired
  EncryptionService encryptionService;

  private NamedCertificateSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedCertificateSecret("Foo")
          .setCa("my-ca")
          .setCertificate("my-cert")
          .setPrivateKey("my-priv");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    afterEach(() -> {
      repository.deleteAll();
    });

    it("updates the secret value with the same name when overwritten", () -> {
      subject.setPrivateKey("first");
      repository.saveAndFlush(subject);
      byte[] firstNonce = subject.getNonce();

      subject.setPrivateKey("second");
      repository.saveAndFlush(subject);

      NamedCertificateSecret second = (NamedCertificateSecret) repository.findOne(subject.getId());
      assertThat(second.getPrivateKey(), equalTo("second"));
      assertThat(Arrays.equals(firstNonce, second.getNonce()), is(false));
    });

    it("only encrypts the value once for the same secret", () -> {
      subject.setPrivateKey("first");
      assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));

      subject.setPrivateKey("first");
      assertThat(((FakeEncryptionService) encryptionService).getEncryptionCount(), equalTo(1));
    });

    it("sets the nonce and the encrypted private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getEncryptedValue(), notNullValue());
      assertThat(subject.getNonce(), notNullValue());
    });

    it("can decrypt the private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getPrivateKey(), equalTo("my-priv"));
    });

    it("allows a null private key", () -> {
      subject.setPrivateKey(null);
      repository.saveAndFlush(subject);
      NamedCertificateSecret secret = (NamedCertificateSecret) repository.findOne(subject.getId());
      assertThat(secret.getPrivateKey(), equalTo(null));
      assertThat(secret.getNonce(), equalTo(null));
    });

    it("allows an empty private key", () -> {
      subject.setPrivateKey("");
      repository.saveAndFlush(subject);
      NamedCertificateSecret secret = (NamedCertificateSecret) repository.findOne(subject.getId());
      assertThat(secret.getPrivateKey(), equalTo(""));
    });
  }
}