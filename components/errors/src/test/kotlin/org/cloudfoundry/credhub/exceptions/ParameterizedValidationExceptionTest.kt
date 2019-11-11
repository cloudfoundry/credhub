package org.cloudfoundry.credhub.exceptions

import org.hamcrest.Matchers.array
import org.hamcrest.core.IsEqual.equalTo
import org.hamcrest.core.IsInstanceOf.instanceOf
import org.junit.Assert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class ParameterizedValidationExceptionTest {

    @Test
    fun exception_extendValidationException() {
        val subject = ParameterizedValidationException(
            "message.code", "foo")
        assertThat(subject, instanceOf(ParameterizedValidationException::class.java))
    }

    @Test
    fun exception_canTakeAMessageCodeWithoutAParamater() {
        val subject = ParameterizedValidationException(
            "message.code")
        assertThat<String>(subject.message, equalTo("message.code"))
        assertThat(subject.getParameters(), equalTo(arrayOf()))
    }

    @Test
    fun exception_canTakeAMessageCodeAndParameterInTheConstructor() {
        val subject = ParameterizedValidationException(
            "message.code", "foo")
        assertThat<String>(subject.message, equalTo("message.code"))
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("foo")))
    }

    @Test
    fun exception_formatsTheOutputOfJsonPathKeysAndRemovesSpecialCharacters() {
        val subject = ParameterizedValidationException(
            "message.code", "$['iasjdoiasd']")
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("iasjdoiasd")))
    }

    @Test
    fun exception_formatsTheOutputOfJsonPathKeysToPutDotsBetweenNestedKeys() {
        var subject = ParameterizedValidationException(
            "message.code", "$['parameters']['alternative_names']")
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("parameters.alternative_names")))

        subject = ParameterizedValidationException("message.code",
            "$['parameters']['alternative_names'][*]")
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("parameters.alternative_names.*")))
    }

    @Test
    fun exception_formatsTheKeysCorrectlyWhenThereAreMultipleParameters() {
        var subject = ParameterizedValidationException(
            "message.code", arrayOf<Any>("$['parameters']['alternative_names']", "$['iasjdoiasd']"))
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("parameters.alternative_names", "iasjdoiasd")))

        subject = ParameterizedValidationException("message.code",
            arrayOf<Any>("$['parameters']['alternative_names'][*]", "$['iasjdoiasd']"))
        assertThat(subject.getParameters(), equalTo(arrayOf<Any>("parameters.alternative_names.*", "iasjdoiasd")))
    }

    @Test
    fun getParameter_returnsAnArrayWithOneParamWhenPresentOrNullWhenNot() {
        var subject = ParameterizedValidationException(
            "message.code", "foo")
        assertThat(subject.getParameters(), array(equalTo<Any>("foo")))

        subject = ParameterizedValidationException("message.code")
        assertThat(subject.getParameters(), equalTo(arrayOf()))
    }
}
