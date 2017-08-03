package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.SshCredential;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.SliceImpl;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {

  private CredentialDataService credentialDataService;

  private CertificateCredential certificateCredential;
  private PasswordCredential passwordCredential;
  private SshCredential sshCredential;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;
  private UUID oldUuid;

  {
    beforeEach(() -> {
      oldUuid = UUID.randomUUID();

      credentialDataService = mock(CredentialDataService.class);

      certificateCredential = mock(CertificateCredential.class);
      passwordCredential = mock(PasswordCredential.class);
      sshCredential = mock(SshCredential.class);

      encryptionKeyCanaryMapper =mock(EncryptionKeyCanaryMapper.class);
      when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
          .thenReturn(newArrayList(oldUuid));
      encryptionKeyCanaryDataService = mock(EncryptionKeyCanaryDataService.class);
      when(credentialDataService.findEncryptedWithAvailableInactiveKey())
          .thenReturn(new SliceImpl<>(asList(certificateCredential, passwordCredential)))
          .thenReturn(new SliceImpl<>(asList(sshCredential)))
          .thenReturn(new SliceImpl<>(new ArrayList<>()));

      final EncryptionKeyRotator encryptionKeyRotator = new EncryptionKeyRotator(credentialDataService, encryptionKeyCanaryMapper, encryptionKeyCanaryDataService);

      encryptionKeyRotator.rotate();
    });

    it("should rotate all the credentials and CAs that were encrypted with an available old key",
        () -> {
          verify(certificateCredential).rotate();
          verify(passwordCredential).rotate();
          verify(sshCredential).rotate();
        });

    it("should save all the credentials, CAs that were rotated", () -> {
      verify(credentialDataService).save(certificateCredential);
      verify(credentialDataService).save(passwordCredential);
      verify(credentialDataService).save(sshCredential);
    });

    it("deletes the unused canaries", () -> {
      ArgumentCaptor<List> argumentCaptor = ArgumentCaptor.forClass(List.class);

      verify(encryptionKeyCanaryDataService).delete(argumentCaptor.capture());

      List<UUID> deletedUuids = argumentCaptor.getValue();

      assertThat(deletedUuids, hasSize(1));
      assertThat(deletedUuids, hasItem(oldUuid));
    });
  }
}
