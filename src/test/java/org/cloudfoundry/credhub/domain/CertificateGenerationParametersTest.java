package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CertificateGenerationParametersTest {

  @Test
  public void constructor_prependsForwardSlashToCaName() throws Exception {
    final CertificateGenerationRequestParameters requestParameters1 = new CertificateGenerationRequestParameters();
    requestParameters1.setCaName("ca-name");
    requestParameters1.setCommonName("a-common-name");
    final CertificateGenerationRequestParameters requestParameters2 = new CertificateGenerationRequestParameters();
    requestParameters2.setCaName("/ca-name");
    requestParameters2.setCommonName("a-common-name");
    final CertificateGenerationParameters parameters1 = new CertificateGenerationParameters(requestParameters1);
    final CertificateGenerationParameters parameters2 = new CertificateGenerationParameters(requestParameters2);

    assertThat(parameters1.equals(parameters2), equalTo(true));
  }

  @Test
  public void equals_returnsTrueWhenKeyUsagesAreIdentical() throws Exception {
    final CertificateGenerationRequestParameters requestParameters1 = new CertificateGenerationRequestParameters();
    final String[] keyUsages1 = new String[]{"data_encipherment", "digital_signature", "non_repudiation", "key_encipherment"};
    final String[] keyUsages2 = new String[]{"digital_signature", "non_repudiation", "key_encipherment", "data_encipherment"};
    requestParameters1.setKeyUsage(keyUsages1);
    requestParameters1.setCommonName("a-common-name");
    final CertificateGenerationRequestParameters requestParameters2 = new CertificateGenerationRequestParameters();
    requestParameters2.setKeyUsage(keyUsages2);
    requestParameters2.setCommonName("a-common-name");

    final CertificateGenerationParameters parameters1 = new CertificateGenerationParameters(requestParameters1);
    final CertificateGenerationParameters parameters2 = new CertificateGenerationParameters(requestParameters2);

    assertThat(parameters1.equals(parameters2), equalTo(true));
  }

  @Test
  public void equals_returnsFalseWhenKeyUsagesAreDifferent() throws Exception {
    final CertificateGenerationRequestParameters requestParameters1 = new CertificateGenerationRequestParameters();
    final String[] keyUsages1 = new String[]{"data_encipherment", "digital_signature", "non_repudiation", "key_encipherment"};
    final String[] keyUsages2 = new String[]{"data_encipherment", "digital_signature", "non_repudiation"};
    requestParameters1.setKeyUsage(keyUsages1);
    requestParameters1.setCommonName("a-common-name");
    final CertificateGenerationRequestParameters requestParameters2 = new CertificateGenerationRequestParameters();
    requestParameters2.setKeyUsage(keyUsages2);
    requestParameters2.setCommonName("a-common-name");

    final CertificateGenerationParameters parameters1 = new CertificateGenerationParameters(requestParameters1);
    final CertificateGenerationParameters parameters2 = new CertificateGenerationParameters(requestParameters2);

    assertThat(parameters1.equals(parameters2), equalTo(false));
  }

  @Test
  public void equals_returnsTrueWhenExtendedKeyUsagesAreIdentical() throws Exception {
    final CertificateGenerationRequestParameters requestParameters1 = new CertificateGenerationRequestParameters();
    final String[] keyUsages1 = new String[]{"server_auth", "client_auth", "code_signing", "email_protection", "timestamping"};
    final String[] keyUsages2 = new String[]{"server_auth", "client_auth", "code_signing", "email_protection", "timestamping"};
    requestParameters1.setExtendedKeyUsage(keyUsages1);
    requestParameters1.setCommonName("a-common-name");
    final CertificateGenerationRequestParameters requestParameters2 = new CertificateGenerationRequestParameters();
    requestParameters2.setExtendedKeyUsage(keyUsages2);
    requestParameters2.setCommonName("a-common-name");

    final CertificateGenerationParameters parameters1 = new CertificateGenerationParameters(requestParameters1);
    final CertificateGenerationParameters parameters2 = new CertificateGenerationParameters(requestParameters2);

    assertThat(parameters1.equals(parameters2), equalTo(true));
  }

  @Test
  public void equals_returnsFalseWhenExtendedKeyUsagesAreDifferent() throws Exception {
    final CertificateGenerationRequestParameters requestParameters1 = new CertificateGenerationRequestParameters();
    final String[] keyUsages1 = new String[]{"server_auth", "client_auth", "code_signing", "email_protection", "timestamping"};
    final String[] keyUsages2 = new String[]{"server_auth", "client_auth", "code_signing", "email_protection"};
    requestParameters1.setExtendedKeyUsage(keyUsages1);
    requestParameters1.setCommonName("a-common-name");
    final CertificateGenerationRequestParameters requestParameters2 = new CertificateGenerationRequestParameters();
    requestParameters2.setExtendedKeyUsage(keyUsages2);
    requestParameters2.setCommonName("a-common-name");

    final CertificateGenerationParameters parameters1 = new CertificateGenerationParameters(requestParameters1);
    final CertificateGenerationParameters parameters2 = new CertificateGenerationParameters(requestParameters2);

    assertThat(parameters1.equals(parameters2), equalTo(false));
  }

}
