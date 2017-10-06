package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.CertificateCredentialVersion;
import io.pivotal.security.entity.CredentialVersion;
import io.pivotal.security.entity.PasswordCredentialVersion;
import io.pivotal.security.entity.RsaCredentialVersion;
import io.pivotal.security.entity.SshCredentialVersion;
import io.pivotal.security.entity.ValueCredentialVersion;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Key;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialRotationTest {
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private Key activeEncryptionKey;

  private Key oldEncryptionKey;

  private UUID activeEncryptionKeyUuid;
  private UUID oldEncryptionKeyUuid;

  private String stringifiedParameters;

  private RetryingEncryptionService encryptionService;
  private Encryptor encryptor;

  @Before
  public void beforeEach() throws Exception {
    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    encryptionService = mock(RetryingEncryptionService.class);
    encryptor = new Encryptor(encryptionService);

    activeEncryptionKey = mock(Key.class);
    oldEncryptionKey = mock(Key.class);

    oldEncryptionKeyUuid = UUID.randomUUID();
    activeEncryptionKeyUuid = UUID.randomUUID();

    when(encryptionKeyCanaryMapper.getActiveUuid()).thenReturn(activeEncryptionKeyUuid);
    when(encryptionKeyCanaryMapper.getActiveKey()).thenReturn(activeEncryptionKey);
    when(encryptionKeyCanaryMapper.getKeyForUuid(activeEncryptionKeyUuid))
        .thenReturn(activeEncryptionKey);
    when(encryptionKeyCanaryMapper.getKeyForUuid(oldEncryptionKeyUuid))
        .thenReturn(oldEncryptionKey);

    when(encryptionService.decrypt(new Encryption(oldEncryptionKeyUuid, "old-encrypted-value".getBytes(), "old-nonce".getBytes())))
        .thenReturn("plaintext");
    when(encryptionService.encrypt("plaintext"))
        .thenReturn(new Encryption(activeEncryptionKeyUuid, "new-encrypted-value".getBytes(),
            "new-nonce".getBytes()));
  }

  @Test
  public void rotate_givenCertificateCredential_reEncryptsWithActiveKey() {
    CertificateCredentialVersion certificateCredentialData = new CertificateCredentialVersion("some-name");
    CertificateCredential credential = new CertificateCredential(certificateCredentialData);

    assertRotation(credential, certificateCredentialData);
  }

  @Test
  public void rotate_givenSshCredential_reEncryptsWithActiveKey() {
    SshCredentialVersion sshCredentialData = new SshCredentialVersion("ssh-key");
    SshCredential credential = new SshCredential(sshCredentialData);

    assertRotation(credential, sshCredentialData);
  }

  @Test
  public void rotate_givenRsaCredential_reEncryptsWithActiveKey() {
    RsaCredentialVersion rsaCredentialData = new RsaCredentialVersion("rsa key");
    RsaCredential credential = new RsaCredential(rsaCredentialData);

    assertRotation(credential, rsaCredentialData);
  }

  @Test
  public void rotate_givenValueCredential_reEncryptsWithActiveKey() {
    ValueCredentialVersion valueCredentialData = new ValueCredentialVersion("value key");
    ValueCredential credential = new ValueCredential(valueCredentialData);

    assertRotation(credential, valueCredentialData);
  }

  @Test
  public void rotate_givenPasswordCredential_reEncryptsPasswordAndParametersWithActiveKey() throws Exception {
    PasswordCredentialVersion passwordCredentialData = new PasswordCredentialVersion("some-name");
    passwordCredentialData.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    passwordCredentialData.setEncryptedValue("old-encrypted-value".getBytes());
    passwordCredentialData.setNonce("old-nonce".getBytes());
    PasswordCredential password = new PasswordCredential(passwordCredentialData);
    password.setEncryptor(encryptor);
    Encryption encryption = new Encryption(oldEncryptionKeyUuid,"old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes());
    passwordCredentialData.setEncryptedGenerationParameters(encryption);


    stringifiedParameters = new ObjectMapper()
        .writeValueAsString(new StringGenerationParameters());

    when(encryptionService
        .decrypt(new Encryption(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(), "old-parameters-nonce".getBytes())))
        .thenReturn(stringifiedParameters);
    when(encryptionService.encrypt(stringifiedParameters))
        .thenReturn(new Encryption(activeEncryptionKeyUuid, "new-encrypted-parameters".getBytes(), "new-nonce-parameters".getBytes()));

    password.rotate();

    assertThat(passwordCredentialData.getEncryptionKeyUuid(),
        equalTo(activeEncryptionKeyUuid));
    assertThat(passwordCredentialData.getEncryptedValue(),
        equalTo("new-encrypted-value".getBytes()));
    assertThat(passwordCredentialData.getNonce(), equalTo("new-nonce".getBytes()));

    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getEncryptedValue(),
        equalTo("new-encrypted-parameters".getBytes()));
    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getNonce(),
        equalTo("new-nonce-parameters".getBytes()));
  }

  private void assertRotation(Credential credential, CredentialVersion delegate) {
    credential.setEncryptor(encryptor);
    delegate.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    delegate.setEncryptedValue("old-encrypted-value".getBytes());
    delegate.setNonce("old-nonce".getBytes());

    credential.rotate();

    assertThat(delegate.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(delegate.getEncryptedValue(), equalTo("new-encrypted-value".getBytes()));
    assertThat(delegate.getNonce(), equalTo("new-nonce".getBytes()));
  }
}
