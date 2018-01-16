package org.cloudfoundry.credhub.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.service.RetryingEncryptionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialRotationTest {

  private UUID activeEncryptionKeyUuid;
  private UUID oldEncryptionKeyUuid;

  private String stringifiedParameters;

  private RetryingEncryptionService encryptionService;
  private Encryptor encryptor;

  @Before
  public void beforeEach() throws Exception {
    encryptionService = mock(RetryingEncryptionService.class);
    encryptor = new Encryptor(encryptionService);

    oldEncryptionKeyUuid = UUID.randomUUID();
    activeEncryptionKeyUuid = UUID.randomUUID();

    when(encryptionService.decrypt(new EncryptedValue(oldEncryptionKeyUuid, "old-encrypted-value".getBytes(), "old-nonce".getBytes())))
        .thenReturn("plaintext");
    when(encryptionService.encrypt("plaintext"))
        .thenReturn(new EncryptedValue(activeEncryptionKeyUuid, "new-encrypted-value".getBytes(),
            "new-nonce".getBytes()));
  }

  @Test
  public void rotate_givenCertificateCredential_reEncryptsWithActiveKey() {
    CertificateCredentialVersionData certificateCredentialData = new CertificateCredentialVersionData("some-name");
    CertificateCredentialVersion credential = new CertificateCredentialVersion(certificateCredentialData);

    assertRotation(credential, certificateCredentialData);
  }

  @Test
  public void rotate_givenSshCredential_reEncryptsWithActiveKey() {
    SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("ssh-key");
    SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData);

    assertRotation(credential, sshCredentialData);
  }

  @Test
  public void rotate_givenRsaCredential_reEncryptsWithActiveKey() {
    RsaCredentialVersionData rsaCredentialData = new RsaCredentialVersionData("rsa key");
    RsaCredentialVersion credential = new RsaCredentialVersion(rsaCredentialData);

    assertRotation(credential, rsaCredentialData);
  }

  @Test
  public void rotate_givenValueCredential_reEncryptsWithActiveKey() {
    ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData("value key");
    ValueCredentialVersion credential = new ValueCredentialVersion(valueCredentialData);

    assertRotation(credential, valueCredentialData);
  }

  @Test
  public void rotate_givenPasswordCredential_reEncryptsPasswordAndParametersWithActiveKey() throws Exception {
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("some-name");
    passwordCredentialData.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(oldEncryptionKeyUuid)
      .setEncryptedValue("old-encrypted-value".getBytes())
      .setNonce("old-nonce".getBytes()));
    PasswordCredentialVersion password = new PasswordCredentialVersion(passwordCredentialData);
    password.setEncryptor(encryptor);
    EncryptedValue encryption = new EncryptedValue(oldEncryptionKeyUuid,"old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes());
    passwordCredentialData.setEncryptedGenerationParameters(encryption);


    stringifiedParameters = new ObjectMapper()
        .writeValueAsString(new StringGenerationParameters());

    when(encryptionService
        .decrypt(new EncryptedValue(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes())))
        .thenReturn(stringifiedParameters);
    when(encryptionService.encrypt(stringifiedParameters))
        .thenReturn(new EncryptedValue(activeEncryptionKeyUuid, "new-encrypted-parameters".getBytes(), "new-nonce-parameters".getBytes()));

    password.rotate();

    assertThat(passwordCredentialData.getEncryptionKeyUuid(),
        equalTo(activeEncryptionKeyUuid));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(),
        equalTo("new-encrypted-value".getBytes()));
    assertThat(passwordCredentialData.getNonce(), equalTo("new-nonce".getBytes()));

    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getEncryptedValue(),
        equalTo("new-encrypted-parameters".getBytes()));
    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getNonce(),
        equalTo("new-nonce-parameters".getBytes()));
  }

  private void assertRotation(CredentialVersion credentialVersion, CredentialVersionData delegate) {
    credentialVersion.setEncryptor(encryptor);
    delegate.setEncryptedValueData(new EncryptedValue()
      .setEncryptionKeyUuid(oldEncryptionKeyUuid)
      .setEncryptedValue("old-encrypted-value".getBytes())
      .setNonce("old-nonce".getBytes()));

    credentialVersion.rotate();

    assertThat(delegate.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(delegate.getEncryptedValueData().getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
    assertThat(delegate.getNonce(), equalTo("new-nonce".getBytes()));
  }
}
