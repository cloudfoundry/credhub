package io.pivotal.security.data;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.repository.EncryptionKeyCanaryRepository;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EncryptionKeyCanaryDataServiceTest {

  @Autowired
  EncryptionKeyCanaryDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      encryptionKeyCanaryRepository.deleteAll();
    });

    describe("#save", () -> {
      it("should save the encryption key in the database", () -> {
        EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
        encryptionKeyCanary.setNonce("test-nonce".getBytes());
        encryptionKeyCanary.setEncryptedValue("test-value".getBytes());
        subject.save(encryptionKeyCanary);

        List<EncryptionKeyCanary> canaries = jdbcTemplate
            .query("select * from encryption_key_canary", (rowSet, rowNum) -> {
              UUID uuid = null;
              try {
                uuid = (UUID) rowSet.getObject("uuid");
              } catch (Exception e) {
                ByteBuffer byteBuffer = ByteBuffer.wrap(rowSet.getBytes("uuid"));
                uuid = new UUID(byteBuffer.getLong(), byteBuffer.getLong());
              }

              EncryptionKeyCanary key = new EncryptionKeyCanary();
              key.setUuid(uuid);
              key.setNonce(rowSet.getBytes("nonce"));
              key.setEncryptedValue(rowSet.getBytes("encrypted_value"));

              return key;
            });

        assertThat(canaries.size(), equalTo(1));

        EncryptionKeyCanary actual = canaries.get(0);

        assertNotNull(actual.getUuid());
        assertThat(actual.getUuid(), equalTo(encryptionKeyCanary.getUuid()));
        assertThat(actual.getNonce(), equalTo("test-nonce".getBytes()));
        assertThat(actual.getEncryptedValue(), equalTo("test-value".getBytes()));
      });
    });

    describe("#findAll", () -> {
      describe("when there are no canaries", () -> {
        it("should return an empty list", () -> {
          assertThat(subject.findAll().size(), equalTo(0));
        });
      });

      describe("when there are canaries", () -> {
        it("should return them as a list", () -> {
          EncryptionKeyCanary firstCanary = new EncryptionKeyCanary();
          EncryptionKeyCanary secondCanary = new EncryptionKeyCanary();

          subject.save(firstCanary);
          subject.save(secondCanary);

          List<EncryptionKeyCanary> canaries = subject.findAll();
          List<UUID> uuids = canaries.stream().map(canary -> canary.getUuid())
              .collect(Collectors.toList());

          assertThat(canaries.size(), equalTo(2));
          assertThat(uuids, containsInAnyOrder(firstCanary.getUuid(), secondCanary.getUuid()));
        });
      });
    });
  }
}
