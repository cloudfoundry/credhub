package org.cloudfoundry.credhub.validator;

import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class MutuallyExclusiveValidator implements ConstraintValidator<MutuallyExclusive, Object> {

  private String[] fields;

  @Override
  public void initialize(MutuallyExclusive constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    String specifiedField = null;

    for (String fieldName : fields) {
      try {
        Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (!StringUtils.isEmpty((String) field.get(value))) {
          if (specifiedField != null) {
            return false;
          } else {
            specifiedField = (String) field.get(value);
          }
        }
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }

    return true;
  }
}
