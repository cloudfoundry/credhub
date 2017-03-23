package io.pivotal.security.view;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;
import org.springframework.test.util.JsonExpectationsHelper;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.json;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateSecretTest {

  private static final JsonExpectationsHelper jsonExpectationsHelper = new JsonExpectationsHelper();
  private ObjectMapper serializingObjectMapper;
  private NamedCertificateSecret entity;
  private String secretName;
  private UUID uuid;
  private Encryptor encryptor;

  {
    beforeEach(() -> {
      UUID canaryUuid = UUID.randomUUID();
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();

      encryptor = mock(Encryptor.class);
      when(encryptor.encrypt("priv")).thenReturn(new Encryption(canaryUuid, encryptedValue, nonce));
      when(encryptor.decrypt(canaryUuid, encryptedValue, nonce)).thenReturn("priv");

      serializingObjectMapper = new ObjectMapper();
      secretName = "/foo";
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
