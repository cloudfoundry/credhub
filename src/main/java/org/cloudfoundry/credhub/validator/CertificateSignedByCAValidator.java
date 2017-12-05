package org.cloudfoundry.credhub.validator;

import org.cloudfoundry.credhub.util.CertificateReader;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CertificateSignedByCAValidator implements ConstraintValidator<RequireCertificateSignedByCA, Object> {

  private String[] fields;

  @Override
  public void initialize(RequireCertificateSignedByCA constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    try {
      Field certificateField = value.getClass().getDeclaredField("certificate");
      Field caField = value.getClass().getDeclaredField("ca");
      certificateField.setAccessible(true);
      caField.setAccessible(true);

      final String certificateValue = (String) certificateField.get(value);
      final String caValue = (String) caField.get(value);

      if (StringUtils.isEmpty(certificateValue) || StringUtils.isEmpty(caValue)) {
        return true;
      }

      final CertificateReader certificateReader = new CertificateReader(certificateValue);
      return certificateReader.isSignedByCa(caValue);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
