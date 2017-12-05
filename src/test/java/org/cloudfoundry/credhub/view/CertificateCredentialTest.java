package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;
import java.util.UUID;

import static org.cloudfoundry.credhub.helper.TestHelper.getBouncyCastleProvider;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateCredentialTest {

  private CertificateCredentialVersion entity;
  private String credentialName;
  private UUID uuid;
  private Encryptor encryptor;


  @Before
  public void beforeEach() {
    getBouncyCastleProvider();
    UUID canaryUuid = UUID.randomUUID();
    byte[] encryptedValue = "fake-encrypted-value".getBytes();
    byte[] nonce = "fake-nonce".getBytes();

    encryptor = mock(Encryptor.class);
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
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
  }

  @Test
  public void createsAViewFromEntity() {
    final CredentialView subject = CertificateView.fromEntity(entity);
    String json = JsonTestHelper.serializeToString(subject);

    assertThat(json, equalTo("{"
        + "\"type\":\"certificate\","
        + "\"transitional\":false,"
        + "\"version_created_at\":null,"
        + "\"id\":\"" + uuid.toString() + "\","
        + "\"name\":\"" + credentialName + "\","
        + "\"value\":{"
        + "\"ca\":\"ca\","
        + "\"certificate\":\"cert\","
        + "\"private_key\":\"priv\""
        + "}"
        + "}"));
  }

  @Test
  public void setsUpdatedAtTimeOnGeneratedView() {
    Instant now = Instant.now();
    entity.setVersionCreatedAt(now);
    final CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
    assertThat(subject.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void setsUUIDOnGeneratedView() {
    CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
    assertThat(subject.getUuid(), equalTo(uuid.toString()));
  }

  @Test
  public void includesKeysWithNullValues() {
    final CredentialView subject = CertificateView
        .fromEntity(new CertificateCredentialVersion(credentialName).setEncryptor(encryptor).setUuid(uuid));
    final String json = JsonTestHelper.serializeToString(subject);

    assertThat(json, equalTo("{"
        + "\"type\":\"certificate\","
        + "\"transitional\":false,"
        + "\"version_created_at\":null,"
        + "\"id\":\""
        + uuid.toString() + "\",\"name\":\""
        + credentialName + "\",\"value\":{"
        + "\"ca\":null,"
        + "\"certificate\":null,"
        + "\"private_key\":null"
        + "}"
        + "}"));
  }
}
