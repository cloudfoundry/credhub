package io.pivotal.security.view;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.repository.SecretRepository;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.util.JsonExpectationsHelper;

import java.time.Instant;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeEncryptionService"})
public class CertificateSecretTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  @Autowired
  SecretRepository secretRepository;

  @Autowired
  ObjectMapper serializingObjectMapper;

  private NamedCertificateSecret entity;

  private String secretName;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      secretName = "foo";
      entity = new NamedCertificateSecret(secretName)
          .setCa("ca")
          .setCertificate("cert")
          .setPrivateKey("priv");
    });

    it("creates a view from entity", () -> {
      final Secret subject = CertificateSecret.fromEntity(entity);
      jsonExpectationsHelper.assertJsonEqual("{\"id\":null,\"type\":\"certificate\",\"updated_at\":null,\"value\":{\"ca\":\"ca\",\"certificate\":\"cert\",\"private_key\":\"priv\"}}", json(subject), true);
    });

    it("sets updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setUpdatedAt(now);
      final CertificateSecret subject = (CertificateSecret) CertificateSecret.fromEntity(entity);
      assertThat(subject.getUpdatedAt(), equalTo(now));
    });

    it("sets uuid on generated view", () -> {
      entity = secretRepository.save(entity);
      CertificateSecret subject = (CertificateSecret) CertificateSecret.fromEntity(entity);
      assertThat(subject.getUuid(), notNullValue());
    });

    it("includes keys with null values", () -> {
      final Secret subject = CertificateSecret.fromEntity(new NamedCertificateSecret(secretName));
      assertThat(serializingObjectMapper.writeValueAsString(subject), equalTo("{\"type\":\"certificate\",\"updated_at\":null,\"id\":null,\"value\":{\"ca\":null,\"certificate\":null,\"private_key\":null}}"));
    });
  }
}
