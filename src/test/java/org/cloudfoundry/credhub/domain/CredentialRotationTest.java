package org.cloudfoundry.credhub.domain;

import java.util.UUID;

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
import org.cloudfoundry.credhub.util.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

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

    when(encryptionService.decrypt(new EncryptedValue(oldEncryptionKeyUuid, "old-encrypted-value".getBytes(StringUtil.UTF_8), "old-nonce".getBytes(StringUtil.UTF_8))))
      .thenReturn("plaintext");
    when(encryptionService.encrypt("plaintext"))
      .thenReturn(new EncryptedValue(activeEncryptionKeyUuid, "new-encrypted-value".getBytes(StringUtil.UTF_8),
        "new-nonce".getBytes(StringUtil.UTF_8)));
  }

  @Test
  public void rotate_givenCertificateCredential_reEncryptsWithActiveKey() {
    final CertificateCredentialVersionData certificateCredentialData = new CertificateCredentialVersionData("some-name");
    final CertificateCredentialVersion credential = new CertificateCredentialVersion(certificateCredentialData);

    assertRotation(credential, certificateCredentialData);
  }

  @Test
  public void rotate_givenSshCredential_reEncryptsWithActiveKey() {
    final SshCredentialVersionData sshCredentialData = new SshCredentialVersionData("ssh-key");
    final SshCredentialVersion credential = new SshCredentialVersion(sshCredentialData);

    assertRotation(credential, sshCredentialData);
  }

  @Test
  public void rotate_givenRsaCredential_reEncryptsWithActiveKey() {
    final RsaCredentialVersionData rsaCredentialData = new RsaCredentialVersionData("rsa key");
    final RsaCredentialVersion credential = new RsaCredentialVersion(rsaCredentialData);

    assertRotation(credential, rsaCredentialData);
  }

  @Test
  public void rotate_givenValueCredential_reEncryptsWithActiveKey() {
    final ValueCredentialVersionData valueCredentialData = new ValueCredentialVersionData("value key");
    final ValueCredentialVersion credential = new ValueCredentialVersion(valueCredentialData);

    assertRotation(credential, valueCredentialData);
  }

  @Test
  public void rotate_givenPasswordCredential_reEncryptsPasswordAndParametersWithActiveKey() throws Exception {

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    encryptedValue.setEncryptedValue("old-encrypted-value".getBytes(StringUtil.UTF_8));
    encryptedValue.setNonce("old-nonce".getBytes(StringUtil.UTF_8));

    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData("some-name");
    passwordCredentialData.setEncryptedValueData(encryptedValue);
    final PasswordCredentialVersion password = new PasswordCredentialVersion(passwordCredentialData);
    password.setEncryptor(encryptor);
    final EncryptedValue encryption = new EncryptedValue(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(StringUtil.UTF_8), "old-parameters-nonce".getBytes(StringUtil.UTF_8));
    passwordCredentialData.setEncryptedGenerationParameters(encryption);


    stringifiedParameters = new ObjectMapper()
      .writeValueAsString(new StringGenerationParameters());

    when(encryptionService
      .decrypt(new EncryptedValue(oldEncryptionKeyUuid, "old-encrypted-parameters".getBytes(StringUtil.UTF_8), "old-parameters-nonce".getBytes(StringUtil.UTF_8))))
      .thenReturn(stringifiedParameters);
    when(encryptionService.encrypt(stringifiedParameters))
      .thenReturn(new EncryptedValue(activeEncryptionKeyUuid, "new-encrypted-parameters".getBytes(StringUtil.UTF_8), "new-nonce-parameters".getBytes(StringUtil.UTF_8)));

    password.rotate();

    assertThat(passwordCredentialData.getEncryptionKeyUuid(),
      equalTo(activeEncryptionKeyUuid));
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(),
      equalTo("new-encrypted-value".getBytes(StringUtil.UTF_8)));
    assertThat(passwordCredentialData.getNonce(), equalTo("new-nonce".getBytes(StringUtil.UTF_8)));

    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getEncryptedValue(),
      equalTo("new-encrypted-parameters".getBytes(StringUtil.UTF_8)));
    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getNonce(),
      equalTo("new-nonce-parameters".getBytes(StringUtil.UTF_8)));
  }

  private void assertRotation(final CredentialVersion credentialVersion, final CredentialVersionData delegate) {
    credentialVersion.setEncryptor(encryptor);

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    encryptedValue.setEncryptedValue("old-encrypted-value".getBytes(StringUtil.UTF_8));
    encryptedValue.setNonce("old-nonce".getBytes(StringUtil.UTF_8));

    delegate.setEncryptedValueData(encryptedValue);

    credentialVersion.rotate();

    assertThat(delegate.getEncryptionKeyUuid(), equalTo(activeEncryptionKeyUuid));
    assertThat(delegate.getEncryptedValueData().getEncryptedValue(), equalTo("new-encrypted-value".getBytes(StringUtil.UTF_8)));
    assertThat(delegate.getNonce(), equalTo("new-nonce".getBytes(StringUtil.UTF_8)));
  }
}
