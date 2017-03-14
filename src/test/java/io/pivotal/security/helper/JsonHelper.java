package io.pivotal.security.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.io.IOException;
import java.util.Set;

import static com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE;
import static io.pivotal.security.util.TimeModuleFactory.createTimeModule;

public class JsonHelper {
  private static final ObjectMapper objectMapper = createObjectMapper();

  private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

  public static ObjectMapper createObjectMapper() {
    return new ObjectMapper()
      .registerModule(createTimeModule())
      .setPropertyNamingStrategy(SNAKE_CASE);
  }

  public static byte[] serialize(Object object) {
    try {
      return objectMapper.writeValueAsBytes(object);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String serializeToString(Object object) {
    try {
      return objectMapper.writeValueAsString(object);
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserialize(byte[] json, Class<T> klass) {
    try {
      return objectMapper.readValue(json, klass);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserialize(String json, Class<T> klass) {
    try {
      return deserializeChecked(json, klass);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> T deserializeChecked(String json, Class<T> klass) throws IOException {
    return objectMapper.readValue(json, klass);
  }

  public static <T> Set<ConstraintViolation<T>> validate(T original) {
    return validator.validate(original);
  }

  public static <T> Set<ConstraintViolation<T>> deserializeAndValidate(String json, Class<T> klass) {
    try {
      T object = objectMapper.readValue(json, klass);
      return validator.validate(object);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static <T> Set<ConstraintViolation<T>> deserializeAndValidate(byte[] json, Class<T> klass) {
    try {
      T object = objectMapper.readValue(json, klass);
      return validator.validate(object);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static Matcher<ConstraintViolation> hasViolationWithMessage(String expectedMessage) {
    return new BaseMatcher<ConstraintViolation>() {
      @Override
      public boolean matches(final Object item) {
        final ConstraintViolation violation = (ConstraintViolation) item;
        return violation.getMessage().equals(expectedMessage);
      }

      @Override
      public void describeTo(final Description description) {
        description.appendText("getMessage() should equal ").appendValue(expectedMessage);
      }
    };
  }
}
