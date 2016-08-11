package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.time.Instant;

import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

@RunWith(Spectrum.class)
public class InstantConverterTest {
  {
    InstantConverter subject = new InstantConverter();

    it("can convert an Instant to the database representation", () -> {
      Instant now = Instant.ofEpochSecond(234234);
      assertThat(subject.convertToDatabaseColumn(now), equalTo(234234L));
    });

    it("can convert a database representation to an Instant", () -> {
      assertThat(subject.convertToEntityAttribute(234234L), equalTo(Instant.ofEpochSecond(234234L)));
    });
  }
}