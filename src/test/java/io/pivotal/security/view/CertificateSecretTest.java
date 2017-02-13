package io.pivotal.security.view;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.JsonExpectationsHelper;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CertificateSecretTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();

  private ObjectMapper serializingObjectMapper;

  private NamedCertificateSecret entity;

  private String secretName;

  private UUID uuid;

  @Autowired
  Encryptor encryptor;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      serializingObjectMapper = new ObjectMapper();
      secretName = "foo";
      uuid = UUID.randomUUID();
      entity = new NamedCertificateSecret(secretName)
          .setEncryptor(encryptor)
          .setCa("ca")
          .setCertificate("cert")
          .setPrivateKey("priv")
          .setUuid(uuid);
    });

    it("creates a view from entity", () -> {
      final SecretView subject = CertificateView.fromEntity(entity);
      jsonExpectationsHelper.assertJsonEqual("{" +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"name\":\"" + secretName + "\"," +
          "\"type\":\"certificate\"," +
          "\"version_created_at\":null," +
          "\"value\":{" +
              "\"ca\":\"ca\"," +
              "\"certificate\":\"cert\"," +
              "\"private_key\":\"priv\"" +
            "}" +
          "}", json(subject), true);
    });

    it("sets updated-at time on generated view", () -> {
      Instant now = Instant.now();
      entity.setVersionCreatedAt(now);
      final CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
      assertThat(subject.getVersionCreatedAt(), equalTo(now));
    });

    it("sets uuid on generated view", () -> {
      CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
      assertThat(subject.getUuid(), equalTo(uuid.toString()));
    });

    it("includes keys with null values", () -> {
      final SecretView subject = CertificateView.fromEntity(new NamedCertificateSecret(secretName).setEncryptor(encryptor).setUuid(uuid));
      assertThat(serializingObjectMapper.writeValueAsString(subject), equalTo("{" +
          "\"type\":\"certificate\"," +
          "\"version_created_at\":null," +
          "\"id\":\"" + uuid.toString() + "\"," +
          "\"name\":\"" + secretName + "\"," +
          "\"value\":{" +
            "\"ca\":null," +
            "\"certificate\":null," +
            "\"private_key\":null" +
          "}" +
        "}"));
    });
  }
}
