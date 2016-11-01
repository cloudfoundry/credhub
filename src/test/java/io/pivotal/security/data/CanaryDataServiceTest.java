package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCanary;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

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
@SpringApplicationConfiguration(CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test"})
public class CanaryDataServiceTest {
  @Autowired
  CanaryDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      jdbcTemplate.execute("delete from named_canary");
    });

    afterEach(() -> {
      jdbcTemplate.execute("delete from named_canary");
    });

    describe("#save", () -> {
      it("should save the canary in the database", () -> {
        NamedCanary canary = new NamedCanary("test-canary");
        canary.setNonce("test-nonce".getBytes());
        canary.setEncryptedValue("test-value".getBytes());
        subject.save(canary);

        List<NamedCanary> canaries = jdbcTemplate.query("select * from named_canary", (rowSet, rowNum) -> {
          NamedCanary namedCanary = new NamedCanary(rowSet.getString("name"));

          namedCanary.setId(rowSet.getLong("id"));
          namedCanary.setNonce(rowSet.getBytes("nonce"));
          namedCanary.setEncryptedValue(rowSet.getBytes("encrypted_value"));

          return namedCanary;
        });

        assertThat(canaries.size(), equalTo(1));

        NamedCanary actual = canaries.get(0);

        assertThat(actual.getId(), equalTo(canary.getId()));
        assertThat(actual.getName(), equalTo("test-canary"));
        assertThat(actual.getNonce(), equalTo("test-nonce".getBytes()));
        assertThat(actual.getEncryptedValue(), equalTo("test-value".getBytes()));
      });
    });

    describe("#find", () -> {
      describe("when there is a canary with that name in the database", () -> {
        it("should return the canary", () -> {
          NamedCanary expected = new NamedCanary("test-canary");
          expected.setEncryptedValue("test-value".getBytes());

          subject.save(expected);
          subject.save(new NamedCanary("foo"));

          NamedCanary actual = subject.find("test-canary");

          assertThat(actual.getId(), equalTo(expected.getId()));
          assertThat(actual.getEncryptedValue(), equalTo(expected.getEncryptedValue()));
        });
      });

      describe("when there is not a canary with that name", () -> {
        it("should return null", () -> {
          subject.save(new NamedCanary("foo"));
          subject.save(new NamedCanary("test"));

          assertNull(subject.find("does-not-exist"));
        });
      });
    });
  }
}
