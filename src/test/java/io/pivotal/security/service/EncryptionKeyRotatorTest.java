package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.junit.runner.RunWith;
import org.springframework.data.domain.SliceImpl;

import java.util.ArrayList;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {
  private SecretEncryptionHelper secretEncryptionHelper;
  private SecretDataService secretDataService;
  private CertificateAuthorityDataService certificateAuthorityDataService;

  private NamedSecret certificateSecret;
  private NamedSecret passwordSecret;
  private NamedSshSecret sshSecret;

  private NamedCertificateAuthority certificateAuthority1;
  private NamedCertificateAuthority certificateAuthority2;
  private NamedCertificateAuthority certificateAuthority3;

  {
    beforeEach(() -> {
      secretEncryptionHelper = mock(SecretEncryptionHelper.class);
      secretDataService = mock(SecretDataService.class);
      certificateAuthorityDataService = mock(CertificateAuthorityDataService.class);

      certificateSecret = new NamedCertificateSecret();
      passwordSecret = new NamedPasswordSecret();
      sshSecret = new NamedSshSecret();

      when(secretDataService.findNotEncryptedByActiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateSecret, passwordSecret)))
          .thenReturn(new SliceImpl<>(asList(sshSecret)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      certificateAuthority1 = new NamedCertificateAuthority();
      certificateAuthority2 = new NamedCertificateAuthority();
      certificateAuthority3 = new NamedCertificateAuthority();

      when(certificateAuthorityDataService.findNotEncryptedByActiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateAuthority1, certificateAuthority2)))
          .thenReturn(new SliceImpl<>(asList(certificateAuthority3)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(secretEncryptionHelper, secretDataService, certificateAuthorityDataService);
      encryptionKeyRotator.rotate();

    });

    it("should rotate all the secrets and CAs that were encrypted with an old key", () -> {
      verify(secretEncryptionHelper).rotate(certificateSecret);
      verify(secretEncryptionHelper).rotate(passwordSecret);
      verify(secretEncryptionHelper).rotate(sshSecret);
      verify(secretEncryptionHelper).rotate(certificateAuthority1);
      verify(secretEncryptionHelper).rotate(certificateAuthority2);
      verify(secretEncryptionHelper).rotate(certificateAuthority3);
    });

    it("should save all the secrets, CAs that were encrypted with an old key", () -> {
      verify(secretDataService).save(certificateSecret);
      verify(secretDataService).save(passwordSecret);
      verify(secretDataService).save(sshSecret);

      verify(certificateAuthorityDataService).save(certificateAuthority1);
      verify(certificateAuthorityDataService).save(certificateAuthority2);
      verify(certificateAuthorityDataService).save(certificateAuthority3);
    });
  }
}
