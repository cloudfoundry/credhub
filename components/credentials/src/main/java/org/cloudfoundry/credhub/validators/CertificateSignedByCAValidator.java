package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.utils.CertificateReader;

public class CertificateSignedByCAValidator implements ConstraintValidator<RequireCertificateSignedByCA, Object> {

  @Override
  public void initialize(final RequireCertificateSignedByCA constraintAnnotation) {
  }

  @Override
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
    try {
      final Field certificateField = value.getClass().getDeclaredField("certificate");
      final Field caField = value.getClass().getDeclaredField("ca");
      certificateField.setAccessible(true);
      caField.setAccessible(true);

      final String certificateValue = (String) certificateField.get(value);
      final String caValue = (String) caField.get(value);

      if (StringUtils.isEmpty(certificateValue) || StringUtils.isEmpty(caValue)) {
        return true;
      }

      final CertificateReader certificateReader = new CertificateReader(certificateValue);
      return certificateReader.isSignedByCa(caValue);

    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new RuntimeException(e);
    }
  }
}
