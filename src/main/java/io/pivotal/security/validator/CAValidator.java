package io.pivotal.security.validator;

import io.pivotal.security.util.CertificateReader;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CAValidator implements ConstraintValidator<RequireValidCA, Object> {

  private String[] fields;

  @Override
  public void initialize(RequireValidCA constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    for (String fieldName : fields) {
      try {
        Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }

        CertificateReader reader = new CertificateReader((String) field.get(value));
        return reader.isValid() && reader.isCa();

      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    return true;
  }
}
