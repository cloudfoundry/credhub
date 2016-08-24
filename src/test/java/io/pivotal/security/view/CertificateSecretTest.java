package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.time.Instant;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class CertificateSecretTest {
  private CertificateSecret subject;
  private NamedCertificateSecret entity;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new CertificateSecret("ca", "cert", "priv");
      entity = new NamedCertificateSecret(uniquify("foo"))
          .setRoot("ca")
          .setCertificate("cert")
          .setPrivateKey("priv");
    });

    it("populates entity with all values", () -> {
      NamedCertificateSecret entity = new NamedCertificateSecret();
      subject.populateEntity(entity);
      assertThat(entity.getRoot(), equalTo("ca"));
      assertThat(entity.getCertificate(), equalTo("cert"));
      assertThat(entity.getPrivateKey(), equalTo("priv"));
    });

    it("creates a view from entity", () -> {
      assertThat(json(new CertificateSecret().generateView(entity)), equalTo("{\"type\":\"certificate\",\"updated_at\":null,\"value\":{\"root\":\"ca\",\"certificate\":\"cert\",\"private_key\":\"priv\"}}"));
    });

    it("set updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setUpdatedAt(now);
      CertificateSecret actual = subject.generateView(entity);
      assertThat(actual.getUpdatedAt(), equalTo(now));
    });
  }
}