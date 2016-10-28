package io.pivotal.security.repository;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedStringSecret;
import io.pivotal.security.entity.NamedValueSecret;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.exparity.hamcrest.BeanMatchers.hasProperty;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SecretRepositoryTest {
  @Autowired
  SecretRepository subject;

  private Consumer<Long> fakeTimeSetter;
  private String secretName;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      secretName = "my-secret";
      fakeTimeSetter.accept(345345L);
    });

    it("can store certificates of length 7000 which means 7016 for GCM", () -> {
      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      NamedCertificateSecret entity = new NamedCertificateSecret(secretName);
      final String longString = stringBuilder.toString();
      entity.setCa(longString);
      entity.setCertificate(longString);
      entity.setPrivateKey(longString);

      subject.save(entity);
      NamedCertificateSecret certificateSecret = (NamedCertificateSecret) subject.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
      assertThat(certificateSecret.getCa().length(), equalTo(7000));
      assertThat(certificateSecret.getCertificate().length(), equalTo(7000));
      assertThat(certificateSecret.getPrivateKey().length(), equalTo(7000));
    });

    it("can store strings of length 7000, which means 7016 for GCM", ()-> {
      final StringBuilder stringBuilder = new StringBuilder(7000);
      Stream.generate(() -> "a").limit(stringBuilder.capacity()).forEach(stringBuilder::append);
      NamedStringSecret entity = new NamedValueSecret(secretName);
      entity.setValue(stringBuilder.toString());

      subject.save(entity);
      assertThat(((NamedStringSecret) subject.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName)).getValue().length(), equalTo(7000));
    });

    it("can fetch credentials sorted in reverse chronological order", () -> {
      String valueName = "value.Secret";
      String passwordName = "password/Secret";
      String certificateName = "certif/ic/atesecret";
      fakeTimeSetter.accept(20000000L);
      subject.save(new NamedValueSecret(valueName));
      subject.save(new NamedPasswordSecret("mySe.cret"));
      fakeTimeSetter.accept(10000000L);
      subject.save(new NamedPasswordSecret(passwordName));
      subject.save(new NamedCertificateSecret("myseecret"));
      fakeTimeSetter.accept(30000000L);
      subject.save(new NamedCertificateSecret(certificateName));

      assertThat(subject.findByNameIgnoreCaseContainingOrderByUpdatedAtDesc("Secret"), IsIterableContainingInOrder.contains(
          hasProperty("name", equalTo(certificateName)),
          hasProperty("name", equalTo(valueName)),
          hasProperty("name", equalTo(passwordName))
      ));
    });

    describe("fetching paths", () -> {
      beforeEach(() -> {
        String valueOther = "fubario";
        String valueName = "value/Secret";
        String passwordName = "password/Secret";
        String certificateName = "certif/ic/ateSecret";
        subject.save(new NamedValueSecret(valueOther));
        subject.save(new NamedValueSecret(valueName));
        subject.save(new NamedPasswordSecret(passwordName));
        subject.save(new NamedCertificateSecret(certificateName));
      });

      it("can fetch all possible paths for all secrets", () -> {
        assertThat(subject.findAllPaths(true), equalTo(newArrayList("certif/", "certif/ic/", "password/", "value/")));
      });

      it("returns an empty list when paths parameter is false", () -> {
        assertThat(subject.findAllPaths(false), equalTo(newArrayList()));
      });
    });
  }
}
