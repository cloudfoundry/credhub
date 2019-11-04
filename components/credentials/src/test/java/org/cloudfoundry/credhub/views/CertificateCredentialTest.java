package org.cloudfoundry.credhub.views;

import java.time.Instant;
import java.util.UUID;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.skyscreamer.jsonassert.JSONAssert;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cloudfoundry.credhub.TestHelper.getBouncyCastleFipsProvider;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.serializeToString;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.PRIVATE_KEY;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
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
  private Instant expiryDate;


  @Before
  public void beforeEach() {
    getBouncyCastleFipsProvider();
    final UUID canaryUuid = UUID.randomUUID();
    final byte[] encryptedValue = "fake-encrypted-value".getBytes(UTF_8);
    final byte[] nonce = "fake-nonce".getBytes(UTF_8);
    expiryDate = Instant.now();

    encryptor = mock(Encryptor.class);
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(PRIVATE_KEY)).thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn(PRIVATE_KEY);

    credentialName = "/foo";
    uuid = UUID.randomUUID();
    entity = new CertificateCredentialVersion(credentialName);
    entity.setEncryptor(encryptor);
    entity.setCa(SELF_SIGNED_CA_CERT);
    entity.setCertificate(SIMPLE_SELF_SIGNED_TEST_CERT);
    entity.setPrivateKey(PRIVATE_KEY);
    entity.setExpiryDate(expiryDate);
    entity.setUuid(uuid);
    entity.setCertificateAuthority(true);
    entity.setSelfSigned(false);
    entity.setGenerated(false);
  }

  @Test
  public void createsAViewFromEntity() throws Exception {
    final CredentialView subject = CertificateView.fromEntity(entity);
    final String actualJson = serializeToString(subject);

    final Instant expiryDateWithoutMillis = Instant.ofEpochSecond(expiryDate.getEpochSecond());

    final String expectedJson = "{"
      + "\"type\":\"certificate\","
      + "\"expiry_date\":\"" + expiryDateWithoutMillis + "\","
      + "\"transitional\":false,"
      + "\"certificate_authority\":true,"
      + "\"self_signed\":false,"
      + "\"generated\":false,"
      + "\"version_created_at\":null,"
      + "\"id\":\"" + uuid.toString() + "\","
      + "\"name\":\"" + credentialName + "\","
      + "\"value\":{"
      + "\"ca\":\"" + SELF_SIGNED_CA_CERT + "\","
      + "\"certificate\":\"" + SIMPLE_SELF_SIGNED_TEST_CERT + "\","
      + "\"private_key\":\"" + PRIVATE_KEY + "\""
      + "}"
      + "}";

    JSONAssert.assertEquals(actualJson, expectedJson, true);
  }

  @Test
  public void setsUpdatedAtTimeOnGeneratedView() {
    final Instant now = Instant.now();
    entity.setVersionCreatedAt(now);
    final CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
    assertThat(subject.getVersionCreatedAt(), equalTo(now));
  }

  @Test
  public void setsUUIDOnGeneratedView() {
    final CertificateView subject = (CertificateView) CertificateView.fromEntity(entity);
    assertThat(subject.getUuid(), equalTo(uuid.toString()));
  }

  @Test
  public void includesKeysWithNullValues() throws Exception {
    final CertificateCredentialVersion certificateCredentialVersion = new CertificateCredentialVersion(credentialName);
    certificateCredentialVersion.setEncryptor(encryptor);
    certificateCredentialVersion.setUuid(uuid);

    final CredentialView subject = CertificateView.fromEntity(certificateCredentialVersion);
    final String actualJson = serializeToString(subject);

    final String expectedJson = "{"
      + "\"type\":\"certificate\","
      + "\"expiry_date\":null,"
      + "\"transitional\":false,"
      + "\"certificate_authority\":false,"
      + "\"self_signed\":false,"
      + "\"version_created_at\":null,"
      + "\"id\":\""
      + uuid.toString() + "\",\"name\":\""
      + credentialName + "\",\"value\":{"
      + "\"ca\":null,"
      + "\"certificate\":null,"
      + "\"private_key\":null"
      + "}"
      + "}";

    JSONAssert.assertEquals(actualJson, expectedJson, true);
  }
}
