package io.pivotal.security.util;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.util.CertificateStringConstants.BIG_TEST_CERT;
import static io.pivotal.security.util.CertificateStringConstants.MISLEADING_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static io.pivotal.security.util.CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS;
import static java.util.Arrays.asList;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import org.junit.runner.RunWith;

import java.security.Security;

@RunWith(Spectrum.class)
public class CertificateReaderTest {
  {
    describe("#isCA", () -> {
      describe("when the certificate has basic constraints", () -> {
        it("sets isCA to true if the basic constraint 'CA' is true", () -> {
          CertificateReader certificateReader = new CertificateReader(SELF_SIGNED_CA_CERT);

          assertThat(certificateReader.isCA(), equalTo(true));
        });

        it("sets isCA to false if the basic constraint 'CA' is not true", () -> {
          CertificateReader certificateReader = new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);

          assertThat(certificateReader.isCA(), equalTo(false));
        });
      });

      describe("when the certificate is x509 v3 and does not have basic constraints", () -> {
        it("sets isCA to false", () -> {
          CertificateReader certificateReader = new CertificateReader(V3_CERT_WITHOUT_BASIC_CONSTRAINTS);

          assertThat(certificateReader.isCA(), equalTo(false));
        });
      });
    });

    describe("#isValid", () -> {
      it("returns true for a valid cert", () -> {
        assertThat(new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT).isValid(), equalTo(true));
        assertThat(new CertificateReader(V3_CERT_WITHOUT_BASIC_CONSTRAINTS).isValid(), equalTo(true));
        assertThat(new CertificateReader(SELF_SIGNED_CA_CERT).isValid(), equalTo(true));
        assertThat(new CertificateReader(BIG_TEST_CERT).isValid(), equalTo(true));
      });

      it("returns false for an invalid cert", () -> {
        assertThat(new CertificateReader("penguin").isValid(), equalTo(false));
        assertThat(new CertificateReader("").isValid(), equalTo(false));
      });
    });

    describe("when it is not a self-signed certificate", () -> {
      it("should correctly set certificate fields", () -> {
        final String distinguishedName = "O=test-org,ST=Jupiter,C=MilkyWay,CN=test-common-name,OU=test-org-unit,L=Europa";
        final GeneralNames generalNames = new GeneralNames(new GeneralName(GeneralName.dNSName, "SolarSystem"));

        CertificateReader certificateReader = new CertificateReader(BIG_TEST_CERT);

        assertThat(certificateReader.getSubjectName().toString(), equalTo(distinguishedName));
        assertThat(certificateReader.getKeyLength(), equalTo(4096));
        assertThat(certificateReader.getAlternativeNames(), equalTo(generalNames));
        assertThat(asList(certificateReader.getExtendedKeyUsage().getUsages()),
            containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
        assertThat(certificateReader.getKeyUsage().hasUsages(KeyUsage.digitalSignature), equalTo(true));
        assertThat(certificateReader.getDurationDays(), equalTo(30));
        assertThat(certificateReader.isSelfSigned(), equalTo(false));
        assertThat(certificateReader.isCA(), equalTo(false));
      });
    });

    describe("when given a simple self-signed certificate", () -> {
      it("should still correctly set up certificate fields", () -> {
        CertificateReader certificateReader = new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);

        assertThat(certificateReader.getSubjectName().toString(), equalTo("CN=foo.example.com"));
        assertThat(certificateReader.getKeyLength(), equalTo(2048));
        assertThat(certificateReader.getAlternativeNames(), equalTo(null));
        assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
        assertThat(certificateReader.getKeyUsage(), equalTo(null));
        assertThat(certificateReader.getDurationDays(), equalTo(365));
        assertThat(certificateReader.isSelfSigned(), equalTo(true));
        assertThat(certificateReader.isCA(), equalTo(false));
      });
    });

    describe("when given a deceptive, not self-signed, certificate", () -> {
      it("should still correctly set up certificate fields", () -> {
        CertificateReader certificateReader = new CertificateReader(MISLEADING_CERT);

        assertThat(certificateReader.getSubjectName().toString(), equalTo("CN=trickster"));
        assertThat(certificateReader.getKeyLength(), equalTo(2048));
        assertThat(certificateReader.getAlternativeNames(), equalTo(null));
        assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
        assertThat(certificateReader.getKeyUsage(), equalTo(null));
        assertThat(certificateReader.getDurationDays(), equalTo(365));
        assertThat(certificateReader.isSelfSigned(), equalTo(false));
        assertThat(certificateReader.isCA(), equalTo(false));
      });
    });

    describe("when given a certificate authority with basic contraints CA: TRUE", () -> {
      it("should return true when asked if it's a CA", () -> {
        CertificateReader certificateReader = new CertificateReader(SELF_SIGNED_CA_CERT);

        assertThat(certificateReader.getSubjectName().toString(), equalTo("CN=foo.com"));
        assertThat(certificateReader.getKeyLength(), equalTo(2048));
        assertThat(certificateReader.getAlternativeNames(), equalTo(null));
        assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
        assertThat(certificateReader.getKeyUsage(), equalTo(null));
        assertThat(certificateReader.getDurationDays(), equalTo(365));
        assertThat(certificateReader.isSelfSigned(), equalTo(true));
        assertThat(certificateReader.isCA(), equalTo(true));
      });
    });
  }
}


