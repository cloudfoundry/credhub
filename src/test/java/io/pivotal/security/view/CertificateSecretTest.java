package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.repository.SecretRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.JsonExpectationsHelper;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.time.Instant;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class CertificateSecretTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  @Autowired
  SecretRepository secretRepository;

  private NamedCertificateSecret entity;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      entity = new NamedCertificateSecret(uniquify("foo"))
          .setCa("ca")
          .setCertificate("cert")
          .setPrivateKey("priv");
    });

    it("creates a view from entity", () -> {
      jsonExpectationsHelper.assertJsonEqual("{\"id\":null,\"type\":\"certificate\",\"updated_at\":null,\"value\":{\"ca\":\"ca\",\"certificate\":\"cert\",\"private_key\":\"priv\"}}", json(CertificateSecret.fromEntity(entity)), true);
    });

    it("sets updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setUpdatedAt(now);
      CertificateSecret actual = (CertificateSecret) CertificateSecret.fromEntity(entity);
      assertThat(actual.getUpdatedAt(), equalTo(now));
    });

    it("sets uuid on generated view", () -> {
      entity = secretRepository.save(entity);
      CertificateSecret actual = (CertificateSecret) CertificateSecret.fromEntity(entity);
      assertThat(actual.getUuid(), notNullValue());
    });
  }
}