package io.pivotal.security.repository;

import com.greghaskins.spectrum.SpringSpectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.StringSecret;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import static com.greghaskins.spectrum.SpringSpectrum.*;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class InMemorySecretStoreTest {

  @Autowired
  InMemorySecretRepository inMemorySecretRepository;

  InMemorySecretStore subject;

  {
    describe("secrets", () -> {
      beforeEach(() -> {
        subject = new InMemorySecretStore(inMemorySecretRepository);
      });

      it("returns null when the store is empty", () -> {
        Assert.assertNull(subject.getStringSecret("whatever"));
      });

      describe("string secrets", () -> {

        StringSecret stringSecret = new StringSecret("doge");

        beforeEach(() -> {
          subject.set("myspecialstringkey", stringSecret);
        });

        it("can be retrieved", () -> {
          assertThat(subject.getStringSecret("myspecialstringkey"), reflectiveEqualTo(stringSecret));
        });

        it("can be retrieved polymorphically", () -> {
          assertThat(subject.getSecret("myspecialstringkey"), reflectiveEqualTo(stringSecret));
        });


        it("can be deleted", () -> {
          assertThat(subject.delete("myspecialstringkey"), is(true));
          Assert.assertNull(subject.getStringSecret("myspecialstringkey"));
          assertThat(subject.delete("myspecialstringkey"), is(false));
        });

        it("setting a stringSecret with the same name overrides the stored stringSecret", () -> {
          StringSecret stringSecret2 = new StringSecret("catz");
          subject.set("myspecialstringkey", stringSecret2);

          assertThat(subject.getStringSecret("myspecialstringkey"), reflectiveEqualTo(stringSecret2));
        });
      });

      describe("certificate secrets", () -> {
        CertificateSecret certificateSecret = new CertificateSecret("my-ca", "my-pub", "my-priv");

        beforeEach(() -> {
          subject.set("myspecialcertkey", certificateSecret);
        });

        it("can be retrieved", () -> {
          assertThat(subject.getCertificateSecret("myspecialcertkey"), reflectiveEqualTo(certificateSecret));
        });

        it("can be retrieved polymorphically", () -> {
          assertThat(subject.getSecret("myspecialcertkey"), reflectiveEqualTo(certificateSecret));
        });

        it("can be deleted", () -> {
          assertThat(subject.delete("myspecialcertkey"), is(true));
          Assert.assertNull(subject.getCertificateSecret("myspecialcertkey"));
          assertThat(subject.delete("myspecialcertkey"), is(false));
        });

        it("setting a stringSecret with the same name overrides the stored stringSecret", () -> {
          CertificateSecret certificateSecret1 = new CertificateSecret("your ca", "your pub", "your priv");
          subject.set("myspecialcertkey", certificateSecret1);

          assertThat(subject.getCertificateSecret("myspecialcertkey"), reflectiveEqualTo(certificateSecret1));
        });
      });
    });
  }
}
