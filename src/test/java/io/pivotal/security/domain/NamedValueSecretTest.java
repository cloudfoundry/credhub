package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedValueSecretTest {
  @Autowired
  public ObjectMapper objectMapper;

  @Autowired
  private Encryptor encryptor;

  NamedValueSecret subject;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new NamedValueSecret("Foo");
    });

    it("returns type value", () -> {
      assertThat(subject.getSecretType(), equalTo("value"));
    });

    describe("with or without alternative names", () -> {
      beforeEach(() -> {
        subject = new NamedValueSecret("foo").setEncryptor(encryptor);
      });

      it("sets the nonce and the encrypted value", () -> {
        subject.setValue("my-value");
        assertThat(subject.getEncryptedValue(), notNullValue());
        assertThat(subject.getNonce(), notNullValue());
      });

      it("can decrypt values", () -> {
        subject.setValue("my-value");
        assertThat(subject.getValue(), equalTo("my-value"));
      });

      itThrows("when setting a value that is null", IllegalArgumentException.class, () -> {
        subject.setValue(null);
      });
    });

    describe(".createNewVersion and #createNewVersion", () -> {
      beforeEach(() -> {
        subject = new NamedValueSecret("/existingName");
        subject.setEncryptor(encryptor);
      });

      it("copies only name from existing", () -> {
        NamedValueSecret newSecret = subject.createNewVersion("new value");

        assertThat(newSecret.getName(), equalTo("/existingName"));
        assertThat(newSecret.getValue(), equalTo("new value"));
      });

      describe("static overload", () -> {
        it("copies values from existing", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            subject,
            "/existingName",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/existingName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });

        it("copies the name from the existing version", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            subject,
            "IAMIGNOREDBECAUSEEXISTINGNAMEISUSED",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/existingName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });

        it("creates new if no existing", () -> {
          NamedValueSecret newSecret = NamedValueSecret.createNewVersion(
            null,
            "/newName",
            "new value",
            encryptor);

          assertThat(newSecret.getName(), equalTo("/newName"));
          assertThat(newSecret.getValue(), equalTo("new value"));
        });
      });
    });

  }
}
