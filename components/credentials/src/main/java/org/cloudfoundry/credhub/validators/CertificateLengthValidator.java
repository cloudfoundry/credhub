package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;

import static java.nio.charset.StandardCharsets.UTF_8;


public class CertificateLengthValidator implements ConstraintValidator<ValidCertificateLength, Object> {

  private String[] fields;

  @Override
  public void initialize(final ValidCertificateLength constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
    for (final String fieldName : fields) {
      try {
        final Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }

        final String certificate = (String) field.get(value);
        if (certificate.getBytes(UTF_8).length > 7000) {
          return false;
        }

      } catch (final NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    return true;
  }
}
