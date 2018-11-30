package org.cloudfoundry.credhub.validator;

import java.lang.reflect.Field;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.util.CertificateReader;

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

        String certificate = (String) field.get(value);
        CertificateReader reader = new CertificateReader(certificate);
        return reader.isCa();
      } catch (MalformedCertificateException e) {
        return false;
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
    return true;
  }
}
