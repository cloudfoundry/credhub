package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.core.env.ConfigurableEnvironment;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.autoTransactional;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.fail;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class DataStoragePropertiesTest {
  @Autowired
  ConfigurableEnvironment environment;

  private DataStorageProperties subject;

  {
    wireAndUnwire(this);
    autoTransactional(this);

    beforeEach(() -> {
      subject = new DataStorageProperties();
      subject.environment = environment;
    });

    describe("when using in-memory data storage", () -> {
      it("sets the dialect to h2", () -> {
        subject.setType("in-memory");

        subject.init();

        assertThat(environment.getProperty("spring.jpa.database-platform"), equalTo("org.hibernate.dialect.H2Dialect"));
      });
    });

    describe("when using postgres data storage", () -> {
      beforeEach(() -> {
        subject.setType("postgres");
        subject.setUsername("postgres");
        subject.setPassword("postgres-password");
      });
      it("sets the url to point to the database", () -> {
        subject.init();

        assertThat(environment.getProperty("spring.datasource.url"), equalTo("jdbc:postgresql://localhost:5432/credhub"));
      });
      it("sets the username and password", () -> {
        subject.init();

        assertThat(environment.getProperty("spring.datasource.username"), equalTo("postgres"));
        assertThat(environment.getProperty("spring.datasource.password"), equalTo("postgres-password"));
      });
      it("sets the dialect to postgres", () -> {
        subject.init();

        assertThat(environment.getProperty("spring.jpa.database-platform"), equalTo("org.hibernate.dialect.PostgreSQLDialect"));
      });
      it("when a username is missing", () -> {
        try {
          subject.setUsername("");
          subject.init();
          fail();
        }
        catch (RuntimeException r) {
          assertThat(r.getMessage(), equalTo("Using a postgres database requires a username."));
        }
      });
      it("creates a new database on start-up and drops it when tearing-down", () -> {
        subject.init();

        assertThat(environment.getProperty("spring.jpa.hibernate.ddl-auto"), equalTo("create-drop"));
      });
    });
  }
}