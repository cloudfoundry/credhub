package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.utils.CertificateReader;

public class CAValidator implements ConstraintValidator<RequireValidCA, Object> {

  @Override
  public void initialize(final RequireValidCA constraintAnnotation) {
  }

  @Override
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
      try {
        final Field certificateField = value.getClass().getDeclaredField("certificate");
        final Field caField = value.getClass().getDeclaredField("ca");

        certificateField.setAccessible(true);
        caField.setAccessible(true);

        final String certificate = (String) certificateField.get(value);
        final String caCertificate = (String) caField.get(value);

        if (StringUtils.isEmpty(caCertificate) || caCertificate.equals(certificate)) {
          return true;
        }

        final CertificateReader reader = new CertificateReader(caCertificate);
        return reader.isCa();
      } catch (final MalformedCertificateException e) {
        return false;
      } catch (final NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      }
    }
}
