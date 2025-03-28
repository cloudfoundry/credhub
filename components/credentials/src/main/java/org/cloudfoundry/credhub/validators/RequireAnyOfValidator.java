package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.StringUtils;

public class RequireAnyOfValidator implements ConstraintValidator<RequireAnyOf, Object> {

  private String[] fields;

  @Override
  public void initialize(final RequireAnyOf constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
    for (final String fieldName : fields) {
      try {
        final Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (!StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }
      } catch (final NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }

    return false;
  }
}
