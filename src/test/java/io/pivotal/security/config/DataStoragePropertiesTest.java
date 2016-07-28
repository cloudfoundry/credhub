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
  private String dbType;
  private String expectedDbUrl;
  private String databasePlatform;

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

    final SuiteBuilder nonInMemoryDbSuite = () -> () -> {
      describe("when using non-in-memory data storage", () -> {
        beforeEach(() -> {
          subject.setType(dbType);
          subject.setUsername("my-username");
          subject.setPassword("my-password");
        });
        it("sets the url to point to the database", () -> {
          subject.init();

          assertThat(environment.getProperty("spring.datasource.url"), equalTo(expectedDbUrl));
        });
        it("sets the username and password", () -> {
          subject.init();

          assertThat(environment.getProperty("spring.datasource.username"), equalTo("my-username"));
          assertThat(environment.getProperty("spring.datasource.password"), equalTo("my-password"));
        });
        it("sets the dialect to " + dbType, () -> {
          subject.init();

          assertThat(environment.getProperty("spring.jpa.database-platform"), equalTo(databasePlatform));
        });
        it("when a username is missing", () -> {
          try {
            subject.setUsername("");
            subject.init();
            fail();
          } catch (RuntimeException r) {
            assertThat(r.getMessage(), equalTo("Using mysql or postgres requires a username."));
          }
        });
        it("does not recreate the database on start-up", () -> {
          subject.init();

          assertThat(environment.getProperty("spring.jpa.hibernate.ddl-auto"), equalTo("update"));
        });
      });
    };

    describe("when using postgres data storage", () -> {
      beforeEach(() -> {
        dbType = "postgres";
        expectedDbUrl = "jdbc:postgresql://localhost:5432/credhub";
        databasePlatform = "org.hibernate.dialect.PostgreSQLDialect";
      });

      describe("must behave like", nonInMemoryDbSuite.build());
    });

    describe("when using mysql data storage", () -> {
      beforeEach(() -> {
        dbType = "mysql";
        subject.setHost("localhost");
        subject.setPort("3306");
        expectedDbUrl = "jdbc:mysql://localhost:3306/credhub";
        databasePlatform = "org.hibernate.dialect.MySQL5InnoDBDialect";
      });

      describe("must behave like", nonInMemoryDbSuite.build());
    });
  }

  interface ThrowingRunnable {
    void run() throws Exception;
  }

  interface SuiteBuilder {
    Spectrum.Block build();
  }

}
