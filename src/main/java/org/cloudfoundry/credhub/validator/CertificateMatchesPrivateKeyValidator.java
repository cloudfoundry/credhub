package org.cloudfoundry.credhub.validator;

import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CertificateMatchesPrivateKeyValidator implements ConstraintValidator<RequireCertificateMatchesPrivateKey, Object> {

  private String[] fields;

  @Override
  public void initialize(RequireCertificateMatchesPrivateKey constraintAnnotation) {
    fields = constraintAnnotation.fields();
  }

  @Override
  public boolean isValid(Object value, ConstraintValidatorContext context) {
    try {
      Field certificateField = value.getClass().getDeclaredField("certificate");
      Field privateKeyField = value.getClass().getDeclaredField("privateKey");
      certificateField.setAccessible(true);
      privateKeyField.setAccessible(true);

      final String certificateValue = (String) certificateField.get(value);
      final String privateKeyValue = (String) privateKeyField.get(value);

      if (StringUtils.isEmpty(certificateValue) || StringUtils.isEmpty(privateKeyValue)) {
        return true;
      }
      CertificateReader reader = new CertificateReader(certificateValue);
      if(!reader.isValid()) {
        return true;
      }

      final X509Certificate certificate = CertificateReader.getCertificate(certificateValue);
      final PublicKey certificatePublicKey = certificate.getPublicKey();

      final PublicKey publicKey = PrivateKeyReader.getPublicKey(privateKeyValue);

      return publicKey.equals(certificatePublicKey);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
