package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.UUID;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EncryptionKeyCanaryDataServiceTest {
  @Autowired
  EncryptionKeyCanaryDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from encryption_key_canary");
    });

    describe("#save", () -> {
      it("should save the encryption key in the database", () -> {
        EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary();
        encryptionKeyCanary.setName("some-name");
        encryptionKeyCanary.setNonce("test-nonce".getBytes());
        encryptionKeyCanary.setEncryptedValue("test-value".getBytes());
        subject.save(encryptionKeyCanary);

        List<EncryptionKeyCanary> canaries = jdbcTemplate.query("select * from encryption_key_canary", (rowSet, rowNum) -> {
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

    describe("#getOne", () -> {
      describe("when there is one encryption key in the database", () -> {
        it("should return that encryption key", () -> {
          EncryptionKeyCanary expected = new EncryptionKeyCanary();
          expected.setName("canary-name");
          expected.setEncryptedValue("test-value".getBytes());
          expected.setNonce("test-nonce".getBytes());

          subject.save(expected);

          EncryptionKeyCanary actual = subject.getOne();

          assertNotNull(actual.getUuid());
          assertThat(actual.getUuid(), equalTo(expected.getUuid()));
          assertThat(actual.getEncryptedValue(), equalTo(expected.getEncryptedValue()));
        });
      });

      describe("when there are multiple canaries in the database", () -> {
        it("should return a canary", () -> {
          EncryptionKeyCanary expected = new EncryptionKeyCanary();
          expected.setName("canary1");
          expected.setEncryptedValue("test-value".getBytes());
          expected.setNonce("test-nonce".getBytes());

          EncryptionKeyCanary secondCanary = new EncryptionKeyCanary();
          secondCanary.setName("canary2");
          secondCanary.setEncryptedValue("second-test-value".getBytes());
          secondCanary.setNonce("second-nonce".getBytes());

          subject.save(expected);
          subject.save(secondCanary);

          EncryptionKeyCanary actual = subject.getOne();

          assertNotNull(actual.getUuid());
          assertNotNull(actual.getEncryptedValue());
          assertNotNull(actual.getNonce());
        });
      });

      describe("when there is no canary in the database", () -> {
        it("should return null", () -> {
          assertNull(subject.getOne());
        });
      });
    });
  }
}
