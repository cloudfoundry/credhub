package org.cloudfoundry.credhub.validator;

import java.lang.reflect.Field;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.util.encoders.DecoderException;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.UnreadableCertificateException;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader.UnsupportedFormatException;

public class CertificateMatchesPrivateKeyValidator implements ConstraintValidator<RequireCertificateMatchesPrivateKey, Object> {

  @Override
  public void initialize(RequireCertificateMatchesPrivateKey constraintAnnotation) {
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

      CertificateReader certificateReader = new CertificateReader(certificateValue);
      final X509Certificate certificate = certificateReader.getCertificate();
      final PublicKey certificatePublicKey = certificate.getPublicKey();

      final PublicKey publicKey = PrivateKeyReader.getPublicKey(privateKeyValue);

      return publicKey.equals(certificatePublicKey);
    } catch (UnsupportedFormatException | PEMException e) {
      throw new ParameterizedValidationException("error.invalid_key_format", e.getMessage());
    } catch (MalformedCertificateException | UnreadableCertificateException e) {
      throw e;
    } catch (DecoderException e) {
      throw new MalformedPrivateKeyException();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
