package org.cloudfoundry.credhub.helpers;

import java.io.IOException;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.util.TimeModuleFactory;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import static com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE;

final public class JsonTestHelper {

  private JsonTestHelper() {
    super();
  }

  private static final ObjectMapper OBJECT_MAPPER = createObjectMapper();

  private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory()
    .getValidator();

  public static ObjectMapper createObjectMapper() {
    return new ObjectMapper()
      .registerModule(TimeModuleFactory.createTimeModule())
      .setPropertyNamingStrategy(SNAKE_CASE);
  }

  public static byte[] serialize(final Object object) {
    try {
      return OBJECT_MAPPER.writeValueAsBytes(object);
    } catch (final JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String serializeToString(final Object object) {
    try {
      return OBJECT_MAPPER.writeValueAsString(object);
    } catch (final JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserialize(final byte[] json, final Class<T> klass) {
    try {
      return OBJECT_MAPPER.readValue(json, klass);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserialize(final String json, final Class<T> klass) {
    try {
      return deserializeChecked(json, klass);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserializeChecked(final String json, final Class<T> klass) throws IOException {
    return OBJECT_MAPPER.readValue(json, klass);
  }

  public static <T> Set<ConstraintViolation<T>> validate(final T original) {
    return VALIDATOR.validate(original);
  }

  public static <T> Set<ConstraintViolation<T>> deserializeAndValidate(final String json,
                                                                       final Class<T> klass) {
    try {
      final T object = OBJECT_MAPPER.readValue(json, klass);
      return VALIDATOR.validate(object);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> Set<ConstraintViolation<T>> deserializeAndValidate(final byte[] json,
                                                                       final Class<T> klass) {
    try {
      final T object = OBJECT_MAPPER.readValue(json, klass);
      return VALIDATOR.validate(object);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static Matcher<ConstraintViolation<?>> hasViolationWithMessage(final String expectedMessage) {
    return new BaseMatcher<ConstraintViolation<?>>() {
      @Override
      public boolean matches(final Object item) {
        final ConstraintViolation<?> violation = (ConstraintViolation<?>) item;
        return violation.getMessage().equals(expectedMessage);
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("getMessage() should equal ").appendValue(expectedMessage);
      }
    };
  }

  public static JsonNode parse(final String jsonString) throws Exception {
    return OBJECT_MAPPER.readTree(jsonString);
  }
}
