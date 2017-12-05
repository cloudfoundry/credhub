package org.cloudfoundry.credhub.validator;

import java.lang.reflect.Field;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.StringUtils;

public class RequireAnyOfValidator implements ConstraintValidator<RequireAnyOf, Object> {

  private String[] fields;

  @Override
  public void initialize(RequireAnyOf constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    for (String fieldName : fields) {
      try {
        Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (!StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }

    return false;
  }
}
