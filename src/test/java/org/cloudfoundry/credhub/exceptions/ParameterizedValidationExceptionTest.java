package org.cloudfoundry.credhub.exceptions;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.Matchers.array;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class ParameterizedValidationExceptionTest {

  @Test
  public void exception_extendValidationException() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", "foo");
    assertThat(subject, instanceOf(ParameterizedValidationException.class));
  }

  @Test
  public void exception_canTakeAMessageCodeWithoutAParamater() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code");
    assertThat(subject.getMessage(), equalTo("message.code"));
    assertThat(subject.getParameters(), equalTo(new Object[]{}));
  }

  @Test
  public void exception_canTakeAMessageCodeAndParameterInTheConstructor() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", "foo");
    assertThat(subject.getMessage(), equalTo("message.code"));
    assertThat(subject.getParameters(), equalTo(new Object[]{"foo"}));
  }

  @Test
  public void exception_formatsTheOutputOfJsonPathKeysAndRemovesSpecialCharacters() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", "$['iasjdoiasd']");
    assertThat(subject.getParameters(), equalTo(new Object[]{"iasjdoiasd"}));
  }

  @Test
  public void exception_formatsTheOutputOfJsonPathKeysToPutDotsBetweenNestedKeys() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", "$['parameters']['alternative_names']");
    assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names"}));

    subject = new ParameterizedValidationException("message.code",
        "$['parameters']['alternative_names'][*]");
    assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names.*"}));
  }

  @Test
  public void exception_formatsTheKeysCorrectlyWhenThereAreMultipleParameters() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", new String[]{"$['parameters']['alternative_names']", "$['iasjdoiasd']"});
    assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names", "iasjdoiasd"}));

    subject = new ParameterizedValidationException("message.code",
        new String[]{"$['parameters']['alternative_names'][*]", "$['iasjdoiasd']"});
    assertThat(subject.getParameters(), equalTo(new Object[]{"parameters.alternative_names.*", "iasjdoiasd"}));
  }

  @Test
  public void getParameter_returnsAnArrayWithOneParamWhenPresentOrNullWhenNot() {
    ParameterizedValidationException subject = new ParameterizedValidationException(
        "message.code", "foo");
    assertThat(subject.getParameters(), array(equalTo("foo")));

    subject = new ParameterizedValidationException("message.code");
    assertThat(subject.getParameters(), equalTo(new Object[]{}));
  }
}
