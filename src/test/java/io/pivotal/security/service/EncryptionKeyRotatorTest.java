package io.pivotal.security.service;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSshSecret;
import java.util.ArrayList;
import org.junit.runner.RunWith;
import org.springframework.data.domain.SliceImpl;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {

  private SecretDataService secretDataService;

  private NamedCertificateSecret certificateSecret;
  private NamedPasswordSecret passwordSecret;
  private NamedSshSecret sshSecret;

  {
    beforeEach(() -> {
      secretDataService = mock(SecretDataService.class);

      certificateSecret = mock(NamedCertificateSecret.class);
      passwordSecret = mock(NamedPasswordSecret.class);
      sshSecret = mock(NamedSshSecret.class);

      when(secretDataService.findEncryptedWithAvailableInactiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateSecret, passwordSecret)))
          .thenReturn(new SliceImpl<>(asList(sshSecret)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(secretDataService);

      encryptionKeyRotator.rotate();
    });

    it("should rotate all the secrets and CAs that were encrypted with an available old key",
        () -> {
          verify(certificateSecret).rotate();
          verify(passwordSecret).rotate();
          verify(sshSecret).rotate();
        });

    it("should save all the secrets, CAs that were rotated", () -> {
      verify(secretDataService).save(certificateSecret);
      verify(secretDataService).save(passwordSecret);
      verify(secretDataService).save(sshSecret);
    });
  }
}
