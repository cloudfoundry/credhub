package io.pivotal.security.repository;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.CertificateCredentialData;
import io.pivotal.security.entity.ValueCredentialData;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialRepositoryTest {

  @Autowired
  CredentialRepository subject;

  @Autowired
  CredentialNameRepository credentialNameRepository;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  private String name;

  private UUID canaryUuid;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      name = "my-credential";
      canaryUuid = encryptionKeyCanaryMapper.getActiveUuid();
    });

    it("can store certificates of length 7000 which means 7016 for GCM", () -> {
      byte[] encryptedValue = new byte[7016];
      Arrays.fill(encryptedValue, (byte) 'A');
      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      CertificateCredentialData entity = new CertificateCredentialData();
      CredentialName credentialName = credentialNameRepository.save(new CredentialName(name));
      final String longString = stringBuilder.toString();
      entity.setCredentialName(credentialName);
      entity.setCa(longString);
      entity.setCertificate(longString);
      entity.setEncryptedValue(encryptedValue);
      entity.setEncryptionKeyUuid(canaryUuid);

      subject.save(entity);
      CertificateCredentialData credentialData = (CertificateCredentialData) subject
          .findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(credentialName.getUuid());
      assertThat(credentialData.getCa().length(), equalTo(7000));
      assertThat(credentialData.getCertificate().length(), equalTo(7000));
      assertThat(credentialData.getEncryptedValue(), equalTo(encryptedValue));
      assertThat(credentialData.getEncryptedValue().length, equalTo(7016));
    });

    it("can store strings of length 7000, which means 7016 for GCM", () -> {
      byte[] encryptedValue = new byte[7016];
      Arrays.fill(encryptedValue, (byte) 'A');

      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      ValueCredentialData entity = new ValueCredentialData();
      CredentialName credentialName = credentialNameRepository.save(new CredentialName(name));
      entity.setCredentialName(credentialName);
      entity.setEncryptedValue(encryptedValue);
      entity.setEncryptionKeyUuid(canaryUuid);

      subject.save(entity);
      assertThat(subject.findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(credentialName.getUuid())
          .getEncryptedValue().length, equalTo(7016));
    });
  }
}
