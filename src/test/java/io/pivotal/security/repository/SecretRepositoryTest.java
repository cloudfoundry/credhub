package io.pivotal.security.repository;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.*;
import org.hamcrest.MatcherAssert;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static org.exparity.hamcrest.BeanMatchers.theSameAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
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
      secretName = uniquify("my-secret");
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
      NamedCertificateSecret certificateSecret = (NamedCertificateSecret) subject.findOneByName(secretName);
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
      assertThat(((NamedStringSecret) subject.findOneByName(secretName)).getValue().length(), equalTo(7000));
    });

    it("canFetchReverseChronologicallySortedCredentials", () -> {
      String valueName = uniquify("value.Secret");
      String passwordName = uniquify("password/Secret");
      String certificateName = uniquify("certif/ic/ateSecret");
      fakeTimeSetter.accept(20000000L);
      subject.save(new NamedValueSecret(valueName));
      subject.save(new NamedPasswordSecret(uniquify("mySe.cret")));
      fakeTimeSetter.accept(10000000L);
      subject.save(new NamedPasswordSecret(passwordName));
      subject.save(new NamedCertificateSecret(uniquify("mysecret")));
      fakeTimeSetter.accept(30000000L);
      subject.save(new NamedCertificateSecret(certificateName));
      List<NamedSecret> expectedResults = newArrayList(
          new NamedCertificateSecret(certificateName).setUpdatedAt(Instant.ofEpochSecond(30000L, 0)),
          new NamedValueSecret(valueName).setUpdatedAt(Instant.ofEpochSecond(20000L, 0)),
          new NamedPasswordSecret(passwordName).setUpdatedAt(Instant.ofEpochSecond(10000L, 0)));

      List<NamedSecret> results = subject.findByNameContainingOrderByUpdatedAtDesc("Secret");
      MatcherAssert.assertThat(results, theSameAs(expectedResults).excludeProperty("Id").excludeProperty("Uuid"));
    });
  }
}
