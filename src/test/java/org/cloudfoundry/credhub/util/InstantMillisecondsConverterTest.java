package org.cloudfoundry.credhub.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class InstantMillisecondsConverterTest {

  InstantMillisecondsConverter subject = new InstantMillisecondsConverter();

  @Test
  public void canConvertAnInstantToTheDBRepresentation() {
    Instant now = Instant.ofEpochMilli(234234123);
    assertThat(subject.convertToDatabaseColumn(now), equalTo(234234123L));
  }

  @Test
  public void canConvertADBRepresentationIntoAnInstant() {
    assertThat(subject.convertToEntityAttribute(234234321L),
        equalTo(Instant.ofEpochMilli(234234321L)));
  }
}
