package io.pivotal.security.service;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import java.util.ArrayList;

import org.junit.runner.RunWith;
import org.springframework.data.domain.SliceImpl;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {

  private CredentialDataService credentialDataService;

  private CertificateCredential certificateSecret;
  private PasswordCredential passwordSecret;
  private SshCredential sshSecret;

  {
    beforeEach(() -> {
      credentialDataService = mock(CredentialDataService.class);

      certificateSecret = mock(CertificateCredential.class);
      passwordSecret = mock(PasswordCredential.class);
      sshSecret = mock(SshCredential.class);

      when(credentialDataService.findEncryptedWithAvailableInactiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateSecret, passwordSecret)))
          .thenReturn(new SliceImpl<>(asList(sshSecret)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(credentialDataService);

      encryptionKeyRotator.rotate();
    });

    it("should rotate all the secrets and CAs that were encrypted with an available old key",
        () -> {
          verify(certificateSecret).rotate();
          verify(passwordSecret).rotate();
          verify(sshSecret).rotate();
        });

    it("should save all the secrets, CAs that were rotated", () -> {
      verify(credentialDataService).save(certificateSecret);
      verify(credentialDataService).save(passwordSecret);
      verify(credentialDataService).save(sshSecret);
    });
  }
}
