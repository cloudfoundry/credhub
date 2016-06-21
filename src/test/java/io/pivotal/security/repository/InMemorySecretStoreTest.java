package io.pivotal.security.repository;

import com.greghaskins.spectrum.SpringSpectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedStringSecret;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import static com.greghaskins.spectrum.SpringSpectrum.*;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@Transactional
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
        Assert.assertNull(subject.getSecret("whatever"));
      });

      describe("existing string secrets", () -> {

        NamedStringSecret stringSecret = new NamedStringSecret("myspecialstringkey").setValue("doge");

        beforeEach(() -> {
          subject.set(stringSecret);
        });

        it("can be retrieved", () -> {
          assertThat(subject.getSecret("myspecialstringkey"), reflectiveEqualTo(stringSecret));
        });

        it("can be deleted", () -> {
          assertThat(subject.delete("myspecialstringkey"), is(true));
          Assert.assertNull(subject.getSecret("myspecialstringkey"));
          assertThat(subject.delete("myspecialstringkey"), is(false));
        });
      });

      describe("new string secrets", () ->{
        NamedStringSecret stringSecret = new NamedStringSecret("newstringkey").setValue("doge");

        it("can be stored for first time, then retrieved", () -> {
          subject.set(stringSecret);
          assertThat(subject.getSecret("newstringkey"), reflectiveEqualTo(stringSecret));
        });

      });

      describe("existing certificate secrets", () -> {
        NamedCertificateSecret certificateSecret = new NamedCertificateSecret("myspecialcertkey")
            .setCa("my-ca")
            .setPub("my-pub")
            .setPriv("my-priv");

        beforeEach(() -> {
          subject.set(certificateSecret);
        });

        it("can be retrieved", () -> {
          assertThat(subject.getSecret("myspecialcertkey"), reflectiveEqualTo(certificateSecret));
        });

        it("can be retrieved polymorphically", () -> {
          assertThat(subject.getSecret("myspecialcertkey"), reflectiveEqualTo(certificateSecret));
        });

        it("can be deleted", () -> {
          assertThat(subject.delete("myspecialcertkey"), is(true));
          Assert.assertNull(subject.getSecret("myspecialcertkey"));
          assertThat(subject.delete("myspecialcertkey"), is(false));
        });
      });

      describe("new certificate secrets", () -> {
        NamedCertificateSecret certificateSecret = new NamedCertificateSecret("newcertkey")
            .setCa("ca")
            .setPub("pub")
            .setPriv("priv");

        it("can be stored for first time, then retrieved", () -> {
          subject.set(certificateSecret);
          assertThat(subject.getSecret("newcertkey"), reflectiveEqualTo(certificateSecret));
        });

      });

      it("changing certificate types", () -> {
        NamedCertificateSecret certificateSecret = new NamedCertificateSecret("stringkey")
            .setCa("ca")
            .setPub("pub")
            .setPriv("priv");
        NamedStringSecret stringSecret = new NamedStringSecret("stringkey").setValue("doge");

        subject.set(certificateSecret);
        try {
          subject.set(stringSecret);
        } catch (DataIntegrityViolationException e) {
          return;
        }
        fail();
      });

    });


  }
}
