package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.util.CertificateStringConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.skyscreamer.jsonassert.JSONAssert;

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
  private Instant expiryDate;


  @Before
  public void beforeEach() {
    getBouncyCastleProvider();
    UUID canaryUuid = UUID.randomUUID();
    byte[] encryptedValue = "fake-encrypted-value".getBytes();
    byte[] nonce = "fake-nonce".getBytes();
    expiryDate = Instant.now();

    encryptor = mock(Encryptor.class);
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(CertificateStringConstants.PRIVATE_KEY)).thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn(CertificateStringConstants.PRIVATE_KEY);

    credentialName = "/foo";
    uuid = UUID.randomUUID();
    entity = new CertificateCredentialVersion(credentialName)
        .setEncryptor(encryptor)
        .setCa(CertificateStringConstants.SELF_SIGNED_CA_CERT)
        .setCertificate(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT)
        .setPrivateKey(CertificateStringConstants.PRIVATE_KEY)
        .setExpiryDate(expiryDate)
        .setUuid(uuid);
  }

  @Test
  public void createsAViewFromEntity() throws Exception {
    final CredentialView subject = CertificateView.fromEntity(entity);
    String actualJson = JsonTestHelper.serializeToString(subject);

    Instant expiryDateWithoutMillis = Instant.ofEpochSecond(expiryDate.getEpochSecond());

    String expectedJson = "{"
        + "\"type\":\"certificate\","
        + "\"expiry_date\":\"" + expiryDateWithoutMillis + "\","
        + "\"transitional\":false,"
        + "\"version_created_at\":null,"
        + "\"id\":\"" + uuid.toString() + "\","
        + "\"name\":\"" + credentialName + "\","
        + "\"value\":{"
        + "\"ca\":\"" + CertificateStringConstants.SELF_SIGNED_CA_CERT + "\","
        + "\"certificate\":\"" + CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT + "\","
        + "\"private_key\":\"" + CertificateStringConstants.PRIVATE_KEY + "\""
        + "}"
        + "}";

    JSONAssert.assertEquals(actualJson, expectedJson, true);
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
  public void includesKeysWithNullValues() throws Exception {
    final CredentialView subject = CertificateView
        .fromEntity(new CertificateCredentialVersion(credentialName).setEncryptor(encryptor).setUuid(uuid));
    final String actualJson = JsonTestHelper.serializeToString(subject);

    String expectedJson = "{"
        + "\"type\":\"certificate\","
        + "\"expiry_date\":null,"
        + "\"transitional\":false,"
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
