package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.fake.FakeEncryptionService;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "FakeEncryptionService"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedCertificateAuthorityTest {

  @Autowired
  CertificateAuthorityDataService certificateAuthorityDataService;

  @Autowired
  EncryptionService encryptionService;

  @Autowired
  private ObjectMapper objectMapper;

  private NamedCertificateAuthority subject;

  {
    wireAndUnwire(this, false);

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

    it("updates the secret value with the same name when overwritten", () -> {
      subject.setPrivateKey("first");
      certificateAuthorityDataService.save(subject);
      byte[] firstNonce = subject.getNonce();

      subject.setPrivateKey("second");
      certificateAuthorityDataService.save(subject);

      NamedCertificateAuthority second = certificateAuthorityDataService.findMostRecent(subject.getName());
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
      certificateAuthorityDataService.save(subject);
      NamedCertificateAuthority secret = certificateAuthorityDataService.findMostRecent(subject.getName());
      assertThat(secret.getPrivateKey(), equalTo(null));
      assertThat(secret.getNonce(), equalTo(null));
    });

    it("allows an empty private key", () -> {
      subject.setPrivateKey("");
      certificateAuthorityDataService.save(subject);
      NamedCertificateAuthority secret = certificateAuthorityDataService.findMostRecent(subject.getName());
      assertThat(secret.getPrivateKey(), equalTo(""));
    });

    it("generateView tells HSM to decrypt the private key", () -> {
      subject.setPrivateKey("abc");
      certificateAuthorityDataService.save(subject);
      NamedCertificateAuthority secret = certificateAuthorityDataService.findMostRecent(subject.getName());
      assertThat(secret.getPrivateKey(), equalTo("abc"));
    });
  }
}
