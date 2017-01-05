package io.pivotal.security.repository;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.helper.EncryptionCanaryHelper;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Stream;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretRepositoryTest {

  @Autowired
  SecretRepository subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  private Consumer<Long> fakeTimeSetter;
  private String secretName;

  private UUID canaryUuid;

  {
    wireAndUnwire(this, true);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from named_secret");
      jdbcTemplate.execute("delete from encryption_key_canary");
      secretName = "my-secret";
      fakeTimeSetter.accept(345345L);

      canaryUuid = EncryptionCanaryHelper.addCanary(encryptionKeyCanaryDataService).getUuid();
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_secret");
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    it("can store certificates of length 7000 which means 7016 for GCM", () -> {
      byte[] encryptedValue = new byte[7016];
      Arrays.fill(encryptedValue, (byte) 'A');
      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      NamedCertificateSecret entity = new NamedCertificateSecret(secretName);
      final String longString = stringBuilder.toString();
      entity.setCa(longString);
      entity.setCertificate(longString);
      entity.setEncryptedValue(encryptedValue);
      entity.setEncryptionKeyUuid(canaryUuid);

      subject.save(entity);
      NamedCertificateSecret certificateSecret = (NamedCertificateSecret) subject.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
      assertThat(certificateSecret.getCa().length(), equalTo(7000));
      assertThat(certificateSecret.getCertificate().length(), equalTo(7000));
      assertThat(certificateSecret.getEncryptedValue(), equalTo(encryptedValue));
      assertThat(certificateSecret.getEncryptedValue().length, equalTo(7016));
    });

    it("can store strings of length 7000, which means 7016 for GCM", ()-> {
      byte[] encryptedValue = new byte[7016];
      Arrays.fill(encryptedValue, (byte) 'A');

      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      NamedStringSecret entity = new NamedValueSecret(secretName);
      entity.setEncryptedValue(encryptedValue);
      entity.setEncryptionKeyUuid(canaryUuid);

      subject.save(entity);
      assertThat((subject.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName)).getEncryptedValue().length, equalTo(7016));
    });
  }
}
