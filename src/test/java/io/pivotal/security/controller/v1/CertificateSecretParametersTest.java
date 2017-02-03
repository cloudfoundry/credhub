package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(Spectrum.class)
public class CertificateSecretParametersTest {

  /**
   * Subject Name: O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa
   * Duration: 30 days
   * Key Length: 4096
   * Alternative Names: SolarSystem
   * Extended Key Usage: server_auth, client_auth
   * Key Usage: digital_signature
   */
  public static final String TEST_CERT = "-----BEGIN CERTIFICATE-----\n" +
      "MIIEbzCCA1egAwIBAgIUYE3pB+BUaAP0YHeofpCmI/xCkmYwDQYJKoZIhvcNAQEL\n" +
      "BQAwDjEMMAoGA1UEAwwDZm9vMB4XDTE3MDIwMzAxNDMzNloXDTE3MDMwNTAxNDMz\n" +
      "NlowfDERMA8GA1UECgwIdGVzdC1vcmcxEDAOBgNVBAgMB0p1cGl0ZXIxETAPBgNV\n" +
      "BAYTCE1pbGt5V2F5MRkwFwYDVQQDDBB0ZXN0LWNvbW1vbi1uYW1lMRYwFAYDVQQL\n" +
      "DA10ZXN0LW9yZy11bml0MQ8wDQYDVQQHDAZFdXJvcGEwggIiMA0GCSqGSIb3DQEB\n" +
      "AQUAA4ICDwAwggIKAoICAQCk+byx2uL5QNAQqdeEWoD0NfuXdbtf/j7orjK7TjCn\n" +
      "djM21HLnIq96hZ+/Vxg30oxjRqAMKDUIj8OTrisorgcgpLNV7NwklPG9A0gv7xdk\n" +
      "YvxhnEnyrztZYiS8sx98YDwjQpJDeA45QX6+/9k8qmXf7XRQRRTqhkG8jpkk0vvj\n" +
      "hvwwTAma+0xALWfVBnhLJz82snJI+ezM9OuwO53iOkziNHNxtuc5sq/AjuDf48O4\n" +
      "HOtxdB27WniL0T3+4Ng8ZRAgMmlSrQdFn6x/Us32VTVLTD4x1s9H4HL3c8LZJaoD\n" +
      "CEKIwFRn2lSko4b4PAUGHZ0KpfeTlur0uR464s4PHh+EV1DOm/R/1/HIQgKanr5B\n" +
      "FzLONAqFPPCMB/hTPli+Q6nez+Q2alpyxEz/QTCTNROKl+opVWJW6gAPMXAkpqc2\n" +
      "bx0O7fRwwF9evVcQ1BZdfWaG3iGqO60o0y7lEAmvlOwnw0JjSta2NDlR0nNp9frx\n" +
      "85USPdMoSBoaAGb+BehbvFsVoRTToxCo0YwCDcGjgacR4oCu5zTZd0KUVlGJ0vpu\n" +
      "OJiUALyYSD/6mN8ZIfPa/rR8PF5ju3JzGd/AEh0F8gfgardLrNHre904/0HwBqvc\n" +
      "ShdSS0XHjA7nTLAyARgLU/E0TIL9DH63tWrB2W+m7vBMkU0fuY5c40QIalT/iGbj\n" +
      "8QIDAQABo1cwVTAWBgNVHREEDzANggtTb2xhclN5c3RlbTAOBgNVHQ8BAf8EBAMC\n" +
      "B4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw\n" +
      "DQYJKoZIhvcNAQELBQADggEBAF6cvPlK7kuoC/EBmTF4OdTrqzKYa4bm47hn0e7V\n" +
      "3fmgt5YJl/HM/wQI5Dw37y5SjtCScvZUJQ7N+vKQ06bPJHea8f3+XwgsM0JpUhkV\n" +
      "djZR9L5LrJdwmhk4arbMLMKeFwB1Xir72trL1DreI/Kzsow0LbMhllLWPyRHmAhr\n" +
      "Kqu/WgGim6m3lVgZdx4o6cguGry+ceiunCwCFL36CL1AdvYL8ZnUlQDT1hNp3anE\n" +
      "QTHPRc0mETzHET0uL+9UpaUxglRPzuxVhyIYimXSiPQlk8K43gmXM8QKi85eo8xD\n" +
      "W5kgC9Eel5YQcs5wUS/1aW72x2D+7DeGxLjFwm0Sy9S8hfI=\n" +
      "-----END CERTIFICATE-----";

  {
    describe("when not given a certificate string", () -> {
      it("constructs DN string correctly from parameters", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .setCountry("My Country")
            .setState("My State")
            .setOrganization("My Organization")
            .setOrganizationUnit("My Organization Unit")
            .setCommonName("My Common Name")
            .setLocality("My Locality");

        assertThat(
            params.getDN().toString(),
            equalTo("O=My Organization,ST=My State,C=My Country,CN=My Common Name,OU=My Organization Unit,L=My Locality")
        );
      });

      it("can add alternative names", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .addAlternativeNames("alternative-name-1", "alternative-name-2");

        ASN1Sequence sequence = ASN1Sequence.getInstance(params.getAlternativeNames());
        assertThat(sequence.getObjectAt(0), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-1")));
        assertThat(sequence.getObjectAt(1), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-2")));
      });

      it("can add extended key usages", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .addExtendedKeyUsage("server_auth", "client_auth", "code_signing", "email_protection", "time_stamping");

        ExtendedKeyUsage extendedKeyUsages = ExtendedKeyUsage.getInstance(params.getExtendedKeyUsage());
        assertThat(extendedKeyUsages.getUsages()[0], equalTo(KeyPurposeId.id_kp_serverAuth));
        assertThat(extendedKeyUsages.getUsages()[1], equalTo(KeyPurposeId.id_kp_clientAuth));
        assertThat(extendedKeyUsages.getUsages()[2], equalTo(KeyPurposeId.id_kp_codeSigning));
        assertThat(extendedKeyUsages.getUsages()[3], equalTo(KeyPurposeId.id_kp_emailProtection));
        assertThat(extendedKeyUsages.getUsages()[4], equalTo(KeyPurposeId.id_kp_timeStamping));
      });

      it("validates extended key usages", () -> {
        try {
          new CertificateSecretParameters().
              setCountry("My Country")
              .addExtendedKeyUsage("client_auth", "server_off");
          fail();
        } catch (ParameterizedValidationException pve) {
          assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_extended_key_usage"));
          assertThat(pve.getParameters()[0], equalTo("server_off"));
        }
      });

      it("can add key usages", () -> {
        CertificateSecretParameters params = new CertificateSecretParameters()
            .setCountry("My Country")
            .addKeyUsage(
                "digital_signature",
                "non_repudiation",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
                "key_cert_sign",
                "crl_sign",
                "encipher_only",
                "decipher_only"
            );

        KeyUsage keyUsages = KeyUsage.getInstance(params.getKeyUsage());
        assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));

        params = new CertificateSecretParameters()
            .setCountry("My Country")
            .addKeyUsage("digital_signature", "non_repudiation", "decipher_only");

        keyUsages = KeyUsage.getInstance(params.getKeyUsage());
        assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
        assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(false));
        assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));
      });

      it("validates key usages", () -> {
        try {
          new CertificateSecretParameters()
              .setCountry("My Country")
              .addKeyUsage("key_agreement", "digital_sinnature");
          fail();
        } catch (ParameterizedValidationException pve) {
          assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_key_usage"));
          assertThat(pve.getParameters()[0], equalTo("digital_sinnature"));
        }
      });

      it("sets default duration to 365 days", () -> {
        assertThat(new CertificateSecretParameters().getDurationDays(), equalTo(365));
      });

      it("sets default key length to 2048 bits", () -> {
        assertThat(new CertificateSecretParameters().getKeyLength(), equalTo(2048));
      });

      itThrowsWithMessage("when duration is less than 1", ParameterizedValidationException.class, "error.invalid_duration", () -> {
        new CertificateSecretParameters()
            .setCommonName("foo")
            .setDurationDays(0)
            .validate();
      });

      itThrowsWithMessage("when duration is greater than 3650", ParameterizedValidationException.class, "error.invalid_duration", () -> {
        new CertificateSecretParameters()
            .setCommonName("foo")
            .setDurationDays(3651)
            .validate();
      });

      itThrowsWithMessage("when all of DN parameters are empty", ParameterizedValidationException.class, "error.missing_certificate_parameters", () -> {
        new CertificateSecretParameters()
            .setOrganization("")
            .setState("")
            .setCountry("")
            .setCommonName("")
            .setOrganizationUnit("")
            .setLocality("").validate();
      });

      describe("when key lengths are invalid", () -> {
        itThrowsWithMessage("when key length is less than 2048", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(1024)
              .validate();
        });

        itThrowsWithMessage("when key length is between 2048 and 3072", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(2222)
              .validate();
        });

        itThrowsWithMessage("when key length is greater than 4096", ParameterizedValidationException.class, "error.invalid_key_length", () -> {
          new CertificateSecretParameters()
              .setCommonName("foo")
              .setKeyLength(9192)
              .validate();
        });
      });
    });

    describe("when given a certificate string", () -> {
      beforeEach(() -> {
        Security.addProvider(new BouncyCastleProvider());
      });

      afterEach(() -> {
        Security.removeProvider("BC");
      });

      it("should correctly parse the DN name", () -> {
        assertThat(new CertificateSecretParameters(TEST_CERT).getDN().toString(),
            equalTo("O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa"));
      });

      it("should set the certificate's key length", () -> {
        assertThat(new CertificateSecretParameters(TEST_CERT).getKeyLength(), equalTo(4096));
      });

      it("sets alternative names", () -> {
        assertThat(
            new CertificateSecretParameters(TEST_CERT).getAlternativeNames(),
            equalTo(new GeneralNames(new GeneralName(GeneralName.dNSName, "SolarSystem")))
        );
      });

      it("sets extended key usage", () -> {
        assertThat(
            asList(new CertificateSecretParameters(TEST_CERT).getExtendedKeyUsage().getUsages()),
            containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth)
        );
      });

      it("sets key usage", () -> {
        assertThat(
            new CertificateSecretParameters(TEST_CERT).getKeyUsage().hasUsages(KeyUsage.digitalSignature),
            equalTo(true)
        );
      });
    });
  }
}
