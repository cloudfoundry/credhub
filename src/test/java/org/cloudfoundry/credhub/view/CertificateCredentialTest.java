package org.cloudfoundry.credhub.view;

import java.time.Instant;
import java.util.UUID;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.helper.JsonTestHelper;
import org.cloudfoundry.credhub.util.CertificateStringConstants;
import org.cloudfoundry.credhub.util.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.cloudfoundry.credhub.helper.TestHelper.getBouncyCastleFipsProvider;
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
    final byte[] encryptedValue = "fake-encrypted-value".getBytes(StringUtil.UTF_8);
    final byte[] nonce = "fake-nonce".getBytes(StringUtil.UTF_8);
    expiryDate = Instant.now();

    encryptor = mock(Encryptor.class);
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(CertificateStringConstants.PRIVATE_KEY)).thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn(CertificateStringConstants.PRIVATE_KEY);

    credentialName = "/foo";
    uuid = UUID.randomUUID();
    entity = new CertificateCredentialVersion(credentialName);
    entity.setEncryptor(encryptor);
    entity.setCa(CertificateStringConstants.SELF_SIGNED_CA_CERT);
    entity.setCertificate(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);
    entity.setPrivateKey(CertificateStringConstants.PRIVATE_KEY);
    entity.setExpiryDate(expiryDate);
    entity.setUuid(uuid);
  }

  @Test
  public void createsAViewFromEntity() throws Exception {
    final CredentialView subject = CertificateView.fromEntity(entity);
    final String actualJson = JsonTestHelper.serializeToString(subject);

    final Instant expiryDateWithoutMillis = Instant.ofEpochSecond(expiryDate.getEpochSecond());

    final String expectedJson = "{"
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
    final String actualJson = JsonTestHelper.serializeToString(subject);

    final String expectedJson = "{"
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
