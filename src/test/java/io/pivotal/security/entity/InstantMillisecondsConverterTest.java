package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;

import java.time.Instant;

import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(Spectrum.class)
public class InstantMillisecondsConverterTest {
  {
    InstantMillisecondsConverter subject = new InstantMillisecondsConverter();

    it("can convert an Instant to the database representation", () -> {
      Instant now = Instant.ofEpochMilli(234234123);
      assertThat(subject.convertToDatabaseColumn(now), equalTo(234234123L));
    });

    it("can convert a database representation to an Instant", () -> {
      assertThat(subject.convertToEntityAttribute(234234321L), equalTo(Instant.ofEpochMilli(234234321L)));
    });
  }
}