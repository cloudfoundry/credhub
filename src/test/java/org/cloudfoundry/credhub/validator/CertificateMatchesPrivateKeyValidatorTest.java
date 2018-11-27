package org.cloudfoundry.credhub.validator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException;
import org.cloudfoundry.credhub.util.TestConstants;
import org.junit.Before;
import org.junit.Test;

import java.security.Security;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

public class CertificateMatchesPrivateKeyValidatorTest {

  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void isValid_shouldThrowAMalformedPrivateKeyException_whenPrivateKeyIsMalformed() {
    CertificateMatchesPrivateKeyValidator certificateMatchesPrivateKeyValidator = new CertificateMatchesPrivateKeyValidator();

    CertificateCredentialValue certificateCredentialValue = new CertificateCredentialValue(
        TestConstants.TEST_CA,
        TestConstants.TEST_CERTIFICATE,
        TestConstants.INVALID_PRIVATE_KEY,
        "some ca name"
    );

    assertThatThrownBy(() -> {
      certificateMatchesPrivateKeyValidator.isValid(certificateCredentialValue, null);
    }).isInstanceOf(MalformedPrivateKeyException.class);
  }
}