package org.cloudfoundry.credhub.domain;

import java.util.UUID;

import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.PRIVATE_KEY;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateCredentialVersionTest {

  private CertificateCredentialVersion subject;
  private CertificateCredentialVersionData certificateCredentialData;

  private UUID canaryUuid;
  private Encryptor encryptor;

  private byte[] encryptedValue;
  private byte[] nonce;

  @Before
  public void setup() {
    TestHelper.getBouncyCastleFipsProvider();
    encryptor = mock(Encryptor.class);

    encryptedValue = "fake-encrypted-value".getBytes(UTF_8);
    nonce = "fake-nonce".getBytes(UTF_8);
    canaryUuid = UUID.randomUUID();

    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt("my-priv"))
      .thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn("my-priv");

    certificateCredentialData = new CertificateCredentialVersionData("/Foo");
    subject = new CertificateCredentialVersion(certificateCredentialData);
    subject.setEncryptor(encryptor);
    subject.setCa(SELF_SIGNED_CA_CERT);
    subject.setCertificate(SIMPLE_SELF_SIGNED_TEST_CERT);
    subject.setPrivateKey(PRIVATE_KEY);
  }

  @Test
  public void getCredentialType_returnsTypeCertificate() {
    assertThat(subject.getCredentialType(), equalTo("certificate"));
  }

  @Test
  public void setPrivateKey_setsEncryptedValueAndNonce() {
    subject.setPrivateKey("my-priv");
    assertThat(certificateCredentialData.getEncryptedValueData().getEncryptedValue(), notNullValue());
    assertThat(certificateCredentialData.getNonce(), notNullValue());
  }

  @Test
  public void getPrivateKey_decryptsPrivateKey() {
    subject.setPrivateKey("my-priv");
    assertThat(subject.getPrivateKey(), equalTo("my-priv"));
  }

  @Test
  public void setCaName_addASlashToCaName() {
    subject.setCaName("something");
    assertThat(subject.getCaName(), equalTo("/something"));

    subject.setCaName("/something");
    assertThat(subject.getCaName(), equalTo("/something"));

    subject.setCaName("");
    assertThat(subject.getCaName(), equalTo(""));

    subject.setCaName(null);
    assertThat(subject.getCaName(), equalTo(null));
  }
}
