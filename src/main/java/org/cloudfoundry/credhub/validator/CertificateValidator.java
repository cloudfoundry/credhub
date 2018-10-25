package org.cloudfoundry.credhub.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException;
import org.cloudfoundry.credhub.util.CertificateReader;

import java.lang.reflect.Field;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CertificateValidator implements ConstraintValidator<RequireValidCertificate, Object> {
  private static final Logger LOGGER = LogManager.getLogger(CertificateValidator.class);
  private String[] fields;

  @Override
  public void initialize(RequireValidCertificate constraintAnnotation) {
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
        new CertificateReader(certificate);

        return true;
      } catch (MalformedCertificateException e) {
        throw e;
      } catch (NoSuchFieldException | IllegalAccessException e) {
        throw new RuntimeException(e);
      } catch (Exception e){
        if(e.getClass().equals(RuntimeException.class) && e.getMessage().contains("java.io.IOException")){
          LOGGER.error("Exception reading certificate", e);
          throw new UnreadableCertificateException();
        }
      }
    }

    return true;
  }
}
