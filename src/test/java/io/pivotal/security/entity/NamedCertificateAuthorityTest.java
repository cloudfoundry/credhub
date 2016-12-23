package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

import java.time.Instant;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "FakeEncryptionService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedCertificateAuthorityTest {
  @Autowired
  EncryptionService encryptionService;

  @Autowired
  private ObjectMapper objectMapper;

  private NamedCertificateAuthority subject;

  {
    wireAndUnwire(this, true);

    beforeEach(() -> {
      subject = new NamedCertificateAuthority("Foo");
      subject.setCertificate("cert");
      subject.setPrivateKey("priv");
      subject.setType("root");
      ((FakeEncryptionService) encryptionService).resetEncryptionCount();
    });

    it("creates a model from entity", () -> {
      UUID uuid = UUID.randomUUID();
      subject.setUuid(uuid);
      CertificateAuthority certificateAuthority = CertificateAuthority.fromEntity(subject);
      String expectedJson = "{" +
          "\"updated_at\":null," +
          "\"type\":\"root\"," +
          "\"value\":{" +
          "\"certificate\":\"cert\"," +
          "\"private_key\":\"priv\"" +
          "}," +
          "\"id\":\"" + uuid.toString() + "\"" +
          "}";
      assertThat(objectMapper.writer().writeValueAsString(certificateAuthority), equalTo(expectedJson));
    });

    it("set updated-at time on generated view", () -> {
      Instant now = Instant.now();
      subject.setUpdatedAt(now);
      CertificateAuthority actual = CertificateAuthority.fromEntity(subject);
      assertThat(actual.getUpdatedAt(), equalTo(now));
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
  }
}
