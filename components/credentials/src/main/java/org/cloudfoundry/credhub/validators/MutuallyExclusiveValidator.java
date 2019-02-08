package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;

public class MutuallyExclusiveValidator implements ConstraintValidator<MutuallyExclusive, Object> {

  private String[] fields;

  @Override
  public void initialize(final MutuallyExclusive constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
    String specifiedField = null;

    for (final String fieldName : fields) {
      try {
        final Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (!StringUtils.isEmpty((String) field.get(value))) {
          if (specifiedField != null) {
            return false;
          } else {
            specifiedField = (String) field.get(value);
          }
        }
      } catch (final NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }

    return true;
  }
}
