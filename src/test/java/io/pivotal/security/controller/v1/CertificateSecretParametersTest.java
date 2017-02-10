package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.util.CertificateStringConstants.BIG_TEST_CERT;
import static io.pivotal.security.util.CertificateStringConstants.MISLEADING_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_TEST_CERT;
import io.pivotal.security.view.ParameterizedValidationException;
import static java.util.Arrays.asList;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import org.junit.runner.RunWith;

import java.security.Security;

@RunWith(Spectrum.class)
public class CertificateSecretParametersTest {
  private CertificateSecretParameters certificateSecretParameters;

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

        ASN1Sequence sequence = ASN1Sequence.getInstance(params.extractAlternativeNames());
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

      describe("when it is not a self-signed certificate", () -> {
        it("should correctly set certificate fields", () -> {
          final String distinguishedName = "O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa";
          final GeneralNames generalNames = new GeneralNames(new GeneralName(GeneralName.dNSName, "SolarSystem"));

          certificateSecretParameters = new CertificateSecretParameters(BIG_TEST_CERT, "some-ca-name");

          assertThat(certificateSecretParameters.getDN().toString(), equalTo(distinguishedName));
          assertThat(certificateSecretParameters.getKeyLength(), equalTo(4096));
          assertThat(certificateSecretParameters.extractAlternativeNames(), equalTo(generalNames));
          assertThat(asList(certificateSecretParameters.getExtendedKeyUsage().getUsages()),
              containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
          assertThat(certificateSecretParameters.getKeyUsage().hasUsages(KeyUsage.digitalSignature), equalTo(true));
          assertThat(certificateSecretParameters.getDurationDays(), equalTo(30));
          assertThat(certificateSecretParameters.getSelfSign(), equalTo(false));
          assertThat(certificateSecretParameters.getCaName(), equalTo("some-ca-name"));
          assertThat(certificateSecretParameters.getIsCA(), equalTo(false));
        });

      });

      describe("when given a simple self-signed certificate", () -> {
        it("should still correctly set up certificate fields", () -> {
          certificateSecretParameters = new CertificateSecretParameters(SIMPLE_TEST_CERT, "my-name");

          assertThat(certificateSecretParameters.getDN().toString(), equalTo("CN=foo.example.com"));
          assertThat(certificateSecretParameters.getKeyLength(), equalTo(2048));
          assertThat(certificateSecretParameters.extractAlternativeNames(), equalTo(null));
          assertThat(certificateSecretParameters.getExtendedKeyUsage(), equalTo(null));
          assertThat(certificateSecretParameters.getKeyUsage(), equalTo(null));
          assertThat(certificateSecretParameters.getDurationDays(), equalTo(365));
          assertThat(certificateSecretParameters.getCaName(), equalTo("my-name"));
          assertThat(certificateSecretParameters.getSelfSign(), equalTo(true));
          assertThat(certificateSecretParameters.getIsCA(), equalTo(false));
        });
      });

      describe("when given a deceptive, not self-signed, certificate", () -> {
        it("should still correctly set up certificate fields", () -> {
          certificateSecretParameters = new CertificateSecretParameters(MISLEADING_CERT, "some-ca-name");

          assertThat(certificateSecretParameters.getDN().toString(), equalTo("CN=trickster"));
          assertThat(certificateSecretParameters.getKeyLength(), equalTo(2048));
          assertThat(certificateSecretParameters.extractAlternativeNames(), equalTo(null));
          assertThat(certificateSecretParameters.getExtendedKeyUsage(), equalTo(null));
          assertThat(certificateSecretParameters.getKeyUsage(), equalTo(null));
          assertThat(certificateSecretParameters.getDurationDays(), equalTo(365));
          assertThat(certificateSecretParameters.getCaName(), equalTo("some-ca-name"));
          assertThat(certificateSecretParameters.getSelfSign(), equalTo(false));
          assertThat(certificateSecretParameters.getIsCA(), equalTo(false));
        });
      });
    });
  }
}
