package org.cloudfoundry.credhub.validators;

import java.lang.reflect.Field;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException;
import org.cloudfoundry.credhub.utils.CertificateReader;

public class CertificateValidator implements ConstraintValidator<RequireValidCertificate, Object> {
  private static final Logger LOGGER = LogManager.getLogger(CertificateValidator.class);
  private String[] fields;

  @Override
  public void initialize(final RequireValidCertificate constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  @SuppressWarnings("PMD.AvoidRethrowingException")
  public boolean isValid(final Object value, final ConstraintValidatorContext context) {
    for (final String fieldName : fields) {
      try {
        final Field field = value.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);

        if (StringUtils.isEmpty((String) field.get(value))) {
          return true;
        }

        final String certificate = (String) field.get(value);
        new CertificateReader(certificate);

        return true;
      } catch (final MalformedCertificateException e) {
        throw e;
      } catch (final NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      } catch (final Exception e) {
        LOGGER.error("Exception reading certificate", e);
        throw new UnreadableCertificateException();
      }
    }

    return true;
  }
}
