package io.pivotal.security.domain;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.service.Encryption;
import java.util.UUID;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class CertificateCredentialTest {

  private CertificateCredential subject;
  private CertificateCredentialData certificateCredentialData;

  private UUID canaryUuid;
  private Encryptor encryptor;

  private byte[] encryptedValue;
  private byte[] nonce;

  @Before
  public void setup() {
    encryptor = mock(Encryptor.class);

    encryptedValue = "fake-encrypted-value".getBytes();
    nonce = "fake-nonce".getBytes();
    canaryUuid = UUID.randomUUID();

    final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt("my-priv"))
        .thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn("my-priv");

    certificateCredentialData = new CertificateCredentialData("/Foo");
    subject = new CertificateCredential(certificateCredentialData)
        .setEncryptor(encryptor)
        .setCa("my-ca")
        .setCertificate("my-cert")
        .setPrivateKey("my-priv");
  }

  @Test
  public void getCredentialType_returnsTypeCertificate() {
    assertThat(subject.getCredentialType(), equalTo("certificate"));
  }

  @Test
  public void setPrivateKey_setsEncryptedValueAndNonce() {
    subject.setPrivateKey("my-priv");
    assertThat(certificateCredentialData.getEncryptedValue(), notNullValue());
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

  @Test
  public void createNewVersion_copiesCaNameFromExisting() {
    setUpEncryptor();
    CertificateCredentialValue certificateValue = new CertificateCredentialValue(
        "ca", "certificate", "new private key", null);
    CertificateCredential newCredential = CertificateCredential
        .createNewVersion(subject, "anything I AM IGNORED", certificateValue, encryptor);

    assertThat(newCredential.getName(), equalTo("/Foo"));
    assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
    assertThat(newCredential.getCa(), equalTo("ca"));
    assertThat(newCredential.getCertificate(), equalTo("certificate"));
    assertThat(newCredential.getCaName(), equalTo(null));
  }

  @Test
  public void createNewVersion_createsNewIfNoExisting() {
    setUpEncryptor();
    CertificateCredentialValue certificateValue = new CertificateCredentialValue(
        "ca", "certificate", "new private key", null);
    CertificateCredential newCredential = CertificateCredential
        .createNewVersion(null, "/newName", certificateValue, encryptor);

    assertThat(newCredential.getName(), equalTo("/newName"));
    assertThat(newCredential.getPrivateKey(), equalTo("new private key"));
    assertThat(newCredential.getCa(), equalTo("ca"));
    assertThat(newCredential.getCertificate(), equalTo("certificate"));
    assertThat(newCredential.getCaName(), equalTo(null));
  }

  private void setUpEncryptor() {
    byte[] encryptedValue = "new-fake-encrypted".getBytes();
    byte[] nonce = "new-fake-nonce".getBytes();
    final Encryption encryption = new Encryption(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt("new private key"))
        .thenReturn(encryption);
    when(encryptor.decrypt(encryption))
        .thenReturn("new private key");
  }
}
