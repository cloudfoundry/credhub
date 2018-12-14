package org.cloudfoundry.credhub.validator;

import java.lang.reflect.Field;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.util.StringUtil;

public class CertificateLengthValidator implements ConstraintValidator<ValidCertificateLength, Object> {

  private String[] fields;

  @Override
  public void initialize(ValidCertificateLength constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    for (String fieldName : fields) {
      try {
        Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        String certificate = (String) field.get(value);

        if (StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }

        if (certificate.getBytes(StringUtil.UTF_8).length > 7000) {
          return false;
        }

      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    return true;
  }
}
