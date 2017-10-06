package io.pivotal.security.view;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.helper.JsonTestHelper;
import io.pivotal.security.service.Encryption;
import org.junit.runner.RunWith;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class CertificateCredentialTest {

  private CertificateCredentialVersion entity;
  private String credentialName;
  private UUID uuid;
  private Encryptor encryptor;

  {
    beforeEach(() -> {
      UUID canaryUuid = UUID.randomUUID();
      byte[] encryptedValue = "fake-encrypted-value".getBytes();
      byte[] nonce = "fake-nonce".getBytes();

      encryptor = mock(Encryptor.class);
      final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
      when(encryptor.encrypt("priv")).thenReturn(encryption);
      when(encryptor.decrypt(encryption)).thenReturn("priv");

      credentialName = "/foo";
      uuid = UUID.randomUUID();
      entity = new CertificateCredentialVersion(credentialName)
          .setEncryptor(encryptor)
          .setCa("ca")
          .setCertificate("cert")
          .setPrivateKey("priv")
          .setUuid(uuid);
    });

    it("creates a view from entity", () -> {
      final CredentialView subject = CertificateView.fromEntity(entity);
      String json = JsonTestHelper.serializeToString(subject);

      assertThat(json, equalTo("{"
          + "\"type\":\"certificate\","
          + "\"version_created_at\":null,"
          + "\"id\":\"" + uuid.toString() + "\","
          + "\"name\":\"" + credentialName + "\","
          + "\"value\":{"
          + "\"ca\":\"ca\","
          + "\"certificate\":\"cert\","
          + "\"private_key\":\"priv\""
          + "}"
          + "}"));
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
      final CredentialView subject = CertificateView
          .fromEntity(new CertificateCredentialVersion(credentialName).setEncryptor(encryptor).setUuid(uuid));
      final String json = JsonTestHelper.serializeToString(subject);

      assertThat(json, equalTo("{"
          + "\"type\":\"certificate\","
          + "\"version_created_at\":null,"
          + "\"id\":\""
          + uuid.toString() + "\",\"name\":\""
          + credentialName + "\",\"value\":{"
          + "\"ca\":null,"
          + "\"certificate\":null,"
          + "\"private_key\":null"
          + "}"
          + "}"));
    });
  }
}
