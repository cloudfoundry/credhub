package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.*;
import org.junit.runner.RunWith;
import org.springframework.data.domain.SliceImpl;

import java.util.ArrayList;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {
  private SecretEncryptionHelper secretEncryptionHelper;
  private SecretDataService secretDataService;

  private NamedSecret certificateSecret;
  private NamedSecret passwordSecret;
  private NamedSshSecret sshSecret;

  {
    beforeEach(() -> {
      secretEncryptionHelper = mock(SecretEncryptionHelper.class);
      secretDataService = mock(SecretDataService.class);

      certificateSecret = new NamedCertificateSecret();
      passwordSecret = new NamedPasswordSecret();
      sshSecret = new NamedSshSecret();

      when(secretDataService.findEncryptedWithAvailableInactiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateSecret, passwordSecret)))
          .thenReturn(new SliceImpl<>(asList(sshSecret)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(secretEncryptionHelper, secretDataService);

      encryptionKeyRotator.rotate();
    });

    it("should rotate all the secrets and CAs that were encrypted with an available old key", () -> {
      verify(secretEncryptionHelper).rotate(certificateSecret);
      verify(secretEncryptionHelper).rotate(passwordSecret);
      verify(secretEncryptionHelper).rotate(sshSecret);
    });

    it("should save all the secrets, CAs that were rotated", () -> {
      verify(secretDataService).save(certificateSecret);
      verify(secretDataService).save(passwordSecret);
      verify(secretDataService).save(sshSecret);
    });
  }
}
