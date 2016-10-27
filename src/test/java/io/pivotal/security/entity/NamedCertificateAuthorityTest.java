package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.repository.NamedCertificateAuthorityRepository;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import java.time.Instant;
import java.util.Arrays;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class NamedCertificateAuthorityTest {

  @Autowired
  NamedCertificateAuthorityRepository repository;

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  private ObjectMapper objectMapper;

  private NamedCertificateAuthority subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedCertificateAuthority("Foo");
      subject.setCertificate("cert");
      subject.setPrivateKey("priv");
      subject.setType("root");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("saves to repository", () -> {
      repository.saveAndFlush(subject);

      NamedCertificateAuthority first = repository.findOneByNameIgnoreCase("Foo");
      assertThat(first.getPrivateKey(), equalTo("priv"));
      assertThat(first.getCertificate(), equalTo("cert"));
      assertThat(first.getType(), equalTo("root"));
    });

    it("creates a model from entity", () -> {
      CertificateAuthority certificateAuthority = CertificateAuthority.fromEntity(subject);
      assertThat(objectMapper.writer().writeValueAsString(certificateAuthority), equalTo("{\"updated_at\":null,\"type\":\"root\",\"value\":{\"certificate\":\"cert\",\"private_key\":\"priv\"}}"));
    });

    it("set updated-at time on generated view", () -> {
      Instant now = Instant.now();
      subject.setUpdatedAt(now);
      CertificateAuthority actual = CertificateAuthority.fromEntity(subject);
      assertThat(actual.getUpdatedAt(), equalTo(now));
    });

    it("updates the secret value with the same name when overwritten", () -> {
      subject.setPrivateKey("first");
      repository.saveAndFlush(subject);
      byte[] firstNonce = subject.getNonce();

      subject.setPrivateKey("second");
      repository.saveAndFlush(subject);

      NamedCertificateAuthority second = repository.findOne(subject.getId());
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
      NamedCertificateAuthority secret = repository.findOne(subject.getId());
      assertThat(secret.getPrivateKey(), equalTo(null));
      assertThat(secret.getNonce(), equalTo(null));
    });

    it("allows an empty private key", () -> {
      subject.setPrivateKey("");
      repository.saveAndFlush(subject);
      NamedCertificateAuthority secret = repository.findOne(subject.getId());
      assertThat(secret.getPrivateKey(), equalTo(""));
    });

    it("generateView tells HSM to decrypt the private key", () -> {
      subject.setPrivateKey("abc");
      repository.saveAndFlush(subject);
      NamedCertificateAuthority secret = repository.findOne(subject.getId());
      assertThat(secret.getPrivateKey(), equalTo("abc"));
    });
  }
}
