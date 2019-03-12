package org.cloudfoundry.credhub.validators;

import java.security.Security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class CertificateMatchesPrivateKeyValidatorTest {

  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }
  }

  @Test
  public void isValid_shouldThrowAMalformedPrivateKeyException_whenPrivateKeyIsMalformed() {
    final CertificateMatchesPrivateKeyValidator certificateMatchesPrivateKeyValidator = new CertificateMatchesPrivateKeyValidator();

    final CertificateCredentialValue certificateCredentialValue = new CertificateCredentialValue(
      TestConstants.TEST_CA,
      TestConstants.TEST_CERTIFICATE,
      TestConstants.INVALID_PRIVATE_KEY,
      "some ca name"
    );

    assertThatThrownBy(() -> {
      certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null);
    }).isInstanceOf(ParameterizedValidationException.class);
  }
}
