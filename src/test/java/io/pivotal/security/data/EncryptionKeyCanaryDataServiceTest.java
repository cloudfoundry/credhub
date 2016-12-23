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

import java.util.List;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNull;

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
      jdbcTemplate.execute("delete from named_canary");
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_canary");
    });

    describe("#save", () -> {
      it("should save the canary in the database", () -> {
        EncryptionKeyCanary canary = new EncryptionKeyCanary("test-canary");
        canary.setNonce("test-nonce".getBytes());
        canary.setEncryptedValue("test-value".getBytes());
        subject.save(canary);

        List<EncryptionKeyCanary> canaries = jdbcTemplate.query("select * from named_canary", (rowSet, rowNum) -> {
          EncryptionKeyCanary encryptionKeyCanary = new EncryptionKeyCanary(rowSet.getString("name"));

          encryptionKeyCanary.setId(rowSet.getLong("id"));
          encryptionKeyCanary.setNonce(rowSet.getBytes("nonce"));
          encryptionKeyCanary.setEncryptedValue(rowSet.getBytes("encrypted_value"));

          return encryptionKeyCanary;
        });

        assertThat(canaries.size(), equalTo(1));

        EncryptionKeyCanary actual = canaries.get(0);

        assertThat(actual.getId(), equalTo(canary.getId()));
        assertThat(actual.getName(), equalTo("test-canary"));
        assertThat(actual.getNonce(), equalTo("test-nonce".getBytes()));
        assertThat(actual.getEncryptedValue(), equalTo("test-value".getBytes()));
      });
    });

    describe("#find", () -> {
      describe("when there is a canary with that name in the database", () -> {
        it("should return the canary", () -> {
          EncryptionKeyCanary expected = new EncryptionKeyCanary("test-canary");
          expected.setEncryptedValue("test-value".getBytes());

          subject.save(expected);
          subject.save(new EncryptionKeyCanary("foo"));

          EncryptionKeyCanary actual = subject.find("test-canary");

          assertThat(actual.getId(), equalTo(expected.getId()));
          assertThat(actual.getEncryptedValue(), equalTo(expected.getEncryptedValue()));
        });
      });

      describe("when there is not a canary with that name", () -> {
        it("should return null", () -> {
          subject.save(new EncryptionKeyCanary("foo"));
          subject.save(new EncryptionKeyCanary("test"));

          assertNull(subject.find("does-not-exist"));
        });
      });
    });
  }
}
