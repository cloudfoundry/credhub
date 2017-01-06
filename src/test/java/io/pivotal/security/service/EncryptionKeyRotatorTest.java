package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.SecretEncryptionHelper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static java.util.Arrays.asList;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {
  private EncryptionKeyRotator subject;

  private SecretEncryptionHelper secretEncryptionHelper;
  private SecretDataService secretDataService;
  private CertificateAuthorityDataService certificateAuthorityDataService;

  private NamedPasswordSecret passwordSecret;
  private NamedCertificateSecret certificateSecret;

  private NamedCertificateAuthority certificateAuthority1;

  private NamedCertificateAuthority certificateAuthority2;

  {
    beforeEach(() -> {
      secretEncryptionHelper = mock(SecretEncryptionHelper.class);
      secretDataService = mock(SecretDataService.class);
      certificateAuthorityDataService = mock(CertificateAuthorityDataService.class);


      certificateSecret = new NamedCertificateSecret();
      passwordSecret = new NamedPasswordSecret();

      when(secretDataService.findAll()).thenReturn(asList(passwordSecret, certificateSecret));

      certificateAuthority1 = new NamedCertificateAuthority();
      certificateAuthority2 = new NamedCertificateAuthority();

      when(certificateAuthorityDataService.findAll()).thenReturn(asList(certificateAuthority1, certificateAuthority2));

      subject = new EncryptionKeyRotator(secretEncryptionHelper, secretDataService, certificateAuthorityDataService);
    });

    it("should rotate all the secrets and CAs", () -> {
      verify(secretEncryptionHelper, times(2)).rotate(any(NamedSecret.class));
      verify(secretEncryptionHelper, times(2)).rotate(any(NamedCertificateAuthority.class));

      verify(secretEncryptionHelper).rotate(passwordSecret);
      verify(secretEncryptionHelper).rotate(certificateSecret);

      verify(secretEncryptionHelper).rotate(certificateAuthority1);
      verify(secretEncryptionHelper).rotate(certificateAuthority2);
    });

    it("should save all the secrets and CAs", () -> {
      verify(secretDataService, times(2)).save(any(NamedSecret.class));
      verify(certificateAuthorityDataService, times(2)).save(any(NamedCertificateAuthority.class));

      verify(secretDataService).save(passwordSecret);
      verify(secretDataService).save(certificateSecret);

      verify(certificateAuthorityDataService).save(certificateAuthority1);
      verify(certificateAuthorityDataService).save(certificateAuthority2);
    });
  }
}
