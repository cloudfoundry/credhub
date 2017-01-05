package io.pivotal.security.entity;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsNull.notNullValue;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class NamedCertificateSecretTest {
  @Autowired
  JdbcTemplate jdbcTemplate;

  private NamedCertificateSecret subject;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      subject = new NamedCertificateSecret("Foo")
          .setCa("my-ca")
          .setCertificate("my-cert")
          .setPrivateKey("my-priv");
    });

    it("returns type certificate", () -> {
      assertThat(subject.getSecretType(), equalTo("certificate"));
    });

    it("sets the nonce and the encrypted private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getEncryptedValue(), notNullValue());
      assertThat(subject.getNonce(), notNullValue());
    });

    it("can decrypt the private key", () -> {
      subject.setPrivateKey("my-priv");
      assertThat(subject.getPrivateKey(), equalTo("my-priv"));
    });

    describe("#getKeyLength", () -> {
      it("should return 0 if there is no certificate", () -> {
        subject = new NamedCertificateSecret("no-cert");

        assertThat(subject.getKeyLength(), equalTo(0));
      });

      it("should return the number of bits used if there is a certificate", () -> {
        subject = new NamedCertificateSecret("long-cert");
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDxjCCAq6gAwIBAgIUQd0bpTfevQEwi2tJPflQJ0Y/VpQwDQYJKoZIhvcNAQEL\n" +
            "BQAwFjEUMBIGA1UEAwwLZGVmYXVsdGNlcnQwHhcNMTYxMDE5MTgyMzA5WhcNMTcx\n" +
            "MDE5MTgyMzA5WjASMRAwDgYDVQQKDAdzb21lb3JnMIICIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAg8AMIICCgKCAgEAmDpjUiOapsu1iMHuyfhd2BqN1ZNZ5YfkiDxGDLT4rv4N\n" +
            "2iZYFyFMLcrfUgNWYJ/f/gNB8arpvjn7IfR8V4H5xbl5FRvVS9Fb4dAdE4Qnpemw\n" +
            "fwlQnu11ijybU1F4oeG6yGfKcue9Rt8OBrp75GYxTeBzh9iJHzW28q5NweS9kbf1\n" +
            "tg/5/eFd9KP40mzaIvwbd5PVwOPOgCTQhVYy7ECaVWjxt6SMjwTsiyGX6++l4vqf\n" +
            "UGao81AKyK1FCJtv8b/QwAf84awB5tzTkYkUHofEVCDA7w7+SFh4hL2lLsa5DkOL\n" +
            "ssKqecV+mgQT4Xyaay9pa4jm2j6MTVrf7IlOV0awIouyRmln4tJHJQhA4GNzxqky\n" +
            "Lmnu7pbb3JXLWdEIztKoNGZzRRNEcgECjXkrEEu9cCsohLGEd3qSLKP5uArU+PIQ\n" +
            "MHQP1BpthU5FKK+RYyh5S3qgoArTe6XL11KdcQl4ofvRfNoZpGCKsqYMWxPfCtCt\n" +
            "VuualGQtdurAKZ82mdqC8kRVkMrpvPDNbR/brZx20hrsFHhealuTgWJzdC+n6BM6\n" +
            "qYppnzaDv6nVKIWM0trvFUH+rgkWpBd81tL3PlfPaJhfI/x6fCpdiO2Jl4DWlyBQ\n" +
            "0Fs4M87gl0+mmE+wyS3Po3DYx8NoArM0rehvz47N4CLD3VeyyVH8/uo7nDvSMKcC\n" +
            "AwEAAaMQMA4wDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAD1Xf8y/V\n" +
            "wtRw0bpOdMxOK2ugcvbYZ7UyCMnayWPG5q2k54pe/xGv3Hehz9drXF37gjj43bG5\n" +
            "HzZAOQsvFst0KpoWHkHGYcQHA46pVRZ9kDZrNR1J7VXbLKF/96WoM1q3ioAuSr6I\n" +
            "nEdMewFXGaVOnZ0jI8+MEjIXwslabuEIqu606Plf64LgJ3cLXAa/gcXRTYUEpJMJ\n" +
            "C04kTEB0Y5G4rosZpXnJAGbIKHjWowW60qAGd9CNpAnVBALt/zNM/ASXtldvXhCJ\n" +
            "K11vPieda683pAv+G00QSeAjLxVkoNdv3r06/IgayiMvgnHUyu3HmHj0IOraNcsW\n" +
            "VCnouU02eiuggA==\n" +
            "-----END CERTIFICATE-----";
        subject.setCertificate(certificate);

        assertThat(subject.getKeyLength(), equalTo(4096));
      });
    });

    describe("#getDurationDays", () -> {
      it("should return 0 if there is no certificate", () -> {
        subject = new NamedCertificateSecret("no-cert");
        assertThat(subject.getDurationDays(), equalTo(0));
      });

      it("should return the number of bits used if there is a certificate", () -> {
        subject = new NamedCertificateSecret("short-lived-cert");
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIICxjCCAa6gAwIBAgIUSf72UsB/fuH0heIF7AxmVyamwgEwDQYJKoZIhvcNAQEL\n" +
            "BQAwFjEUMBIGA1UEAwwLZGVmYXVsdGNlcnQwHhcNMTYxMDE5MTgyMzI4WhcNMTYx\n" +
            "MTE4MTgyMzI4WjASMRAwDgYDVQQKDAdzb21lb3JnMIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAsgM7f9ARLvZ99bv4I7AmkB3lH1ZxeKGaCJeu8+iOqCNt\n" +
            "GiP5iPmob42T3WEWXmCA6S5Rnp/P0jKmjAaK7rak8/G7qtHvzij8eUcgLrTDgzrR\n" +
            "3SThlkF4jKiJk6ucWOdzDl0WiuiGUB7M1ergSxuZRIe+D7k3gKdxtLRuZT0rCmP6\n" +
            "FPTMfg4MABRfw21WLO22T4KRwpun2JduOJ+6Jb8Bw3dPW5gL0R9IhCfyCXaU5o1Q\n" +
            "UMIE0GQ0x/UEKPY8E2xAJeFA5r5NXmbttWeIr68jRp3rALnldIj6N9TeAFdBryO2\n" +
            "o2jegm1bpciYVq/J2MNVBwI2kID+KkpGVU5bJ5QXSQIDAQABoxAwDjAMBgNVHRMB\n" +
            "Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAc5w9GSgE0bQLmm/Ah3MtF182+OP9d\n" +
            "/qIoW9YP9wALdohM6cTOQ5+2A9yC8aCeJ0mKYPiYKmADSD11Vu7Gu0meLa/QTHsk\n" +
            "2vfmG/5Kl2R42uAqCEdbJWRW4B9HOyQkb4IzlTxEKgnEfd531A+V/lH0hsQikwSe\n" +
            "X0vUHq6ml5ujG1bHAUlLiaY7orOGjvb9iVI1YQ1V2g7kVmcgMUku2HECevm6/2lN\n" +
            "FUsU2vrYze8SoCHJa0UR6Hp0H+IDY6Cbbe2M7CpNYXKmE11+JqoM3u/FpY9alNFy\n" +
            "vZ6cP7dvlUjlnyfzPPrV9dweJ874P9bJPeK2YFR9Bk2mn/xv010Bf9gI\n" +
            "-----END CERTIFICATE-----";
        subject.setCertificate(certificate);

        assertThat(subject.getDurationDays(), equalTo(30));
      });
    });

    describe("#getAlternativeNames", () -> {
      it("should return null if there is no certificate", () -> {
        subject = new NamedCertificateSecret("no-alternative-names");

        assertThat(subject.getAlternativeNames(), nullValue());
      });

      it("should return the alternative names if the certificate has any", () -> {
        subject = new NamedCertificateSecret("cert-with-alternative-names");
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDFjCCAf6gAwIBAgIUemSYe8YUsU8e1YEJQ0FIbY/Sf68wDQYJKoZIhvcNAQEL\n" +
            "BQAwFjEUMBIGA1UEAwwLZGVmYXVsdGNlcnQwHhcNMTYxMDE5MjA0NjU1WhcNMTcx\n" +
            "MDE5MjA0NjU1WjAmMSQwIgYDVQQDDBtjZXJ0LXdpdGgtYWx0ZXJuYXRpdmUtbmFt\n" +
            "ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvN2SKEPqoIJQkUlbZ\n" +
            "2nAKJFTq20R0O6k12osOKkWVRUU5kwPh/3C/I1bCFLUST1QdktYWpWwY4SmAdjxL\n" +
            "ZP9xFj+VFvng8ifofLaJ0/ug3L2HDxEJzh3p3Ijt/sFiPQC3bZo+zPim3WlsGRbe\n" +
            "894bUc6FpnT68gQex4Y5W1hY085HKVqZ/q/TazT5ZuBBsADeSWhBL4o+BWpeZaBy\n" +
            "XopdkdveRADdVDOnHlw4K+A8qMbR/hoYzUVFu0rrWcv1suyJJwgNtz9qu7YcCPly\n" +
            "18sEVN8ZxuQwTp4ljoubuG3IAyk5+Uc6zrCchXtwxAppUH1Yet10ghaAoI1Isi3v\n" +
            "tH53AgMBAAGjTDBKMDoGA1UdEQQzMDGCFXNvbWUtYWx0ZXJuYXRpdmUtbmFtZYIY\n" +
            "YW5vdGhlci1hbHRlcm5hdGl2ZS1uYW1lMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcN\n" +
            "AQELBQADggEBAJv9m2LzVs9kvv2+c/LDF9pQocP2LnInA7EipUR1LfW8nl8qdiD2\n" +
            "IepKQSyC2ItvBgYgl6e2DhtIKT5Ihn7yo+5jPQ21U2PQRVjo+7XlYVvOxd4EdSqg\n" +
            "u65aTQaXdrNbkN1b9Z6FjwERPiLKBP2TqAzmrOQ7MzWsXvF3EEun8xceMGu//+L8\n" +
            "7UNgDe6W9aAuE6BgehN67rF2xjvisOyCNhBkUx5ob99G6ATucSPlQCkgmguUxAWt\n" +
            "ghWbrjcsY2o52ynxIfMKK9dUpjdxR3ZfkQuOjJOExvuCD2qIdGZD25qVI83ANGkG\n" +
            "D6cnO6EPORZu5vEAa0Tw3Jt/oyHTPJs+OK0=\n" +
            "-----END CERTIFICATE-----";
        subject.setCertificate(certificate);

        ASN1Sequence sequence = (ASN1Sequence) subject.getAlternativeNames().getParsedValue();
        assertThat(((DERTaggedObject) sequence.getObjectAt(0)).getEncoded(), equalTo(new GeneralName(GeneralName.dNSName, "some-alternative-name").getEncoded()));
        assertThat(((DERTaggedObject) sequence.getObjectAt(1)).getEncoded(), equalTo(new GeneralName(GeneralName.dNSName, "another-alternative-name").getEncoded()));
      });
    });

    describe("getting key usages and extended key usages", () -> {
      it("should return null if there is no certificate", () -> {
        subject = new NamedCertificateSecret("no-alternative-names");

        assertThat(subject.getKeyUsage(), nullValue());
        assertThat(subject.getExtendedKeyUsage(), nullValue());
      });

      it("should return the key usages if the certificate has any", () -> {
        subject = new NamedCertificateSecret("cert-with-extensions");
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIC/TCCAeWgAwIBAgIUec/ef30N/nuZEqNk1CSQ5Rk3v9cwDQYJKoZIhvcNAQEL\n" +
            "BQAwDzENMAsGA1UEAwwEcm9vdDAeFw0xNzAxMDUxOTI2MTdaFw0xODAxMDUxOTI2\n" +
            "MTdaMCExHzAdBgNVBAMMFmNlcnRpZmljYXRlLTE0ODM2NDQzNzcwggEiMA0GCSqG\n" +
            "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCej4HhEvVStRZ9MIo7LDaAY8Z1ol8QY47U\n" +
            "iKKBNFHV70BY5z2tHGnl49uscxJL4LUjGM3zrCNq9v0yee5+Cfgmx1CN5InFclf6\n" +
            "pVDcg8cxDJpJkvkUE/nUHWgBdUE9fMpHunrD+iPDioAUfY6C16V1UfWEEh82mQOB\n" +
            "RZTl4M8X1s9BZf1SqNJ6lwwG9ay8+Cu2H7RnYTI14LX4yCyJBazmf1jMXSgi0gCD\n" +
            "NbQtVusWotFGZ/sYgfrYLf6QkZsnFkcK6cqoAA7PfaOeppGn/J5b6Y293OOcaF9a\n" +
            "hmKN1Zi5k4YUxl6SS2gwR2yq6VmkcDsmC/eYTG77VE3uAzoFl8bdAgMBAAGjPzA9\n" +
            "MA4GA1UdDwEB/wQEAwIDiDAdBgNVHSUEFjAUBggrBgEFBQcDAwYIKwYBBQUHAwQw\n" +
            "DAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAzGGF5BATBy0oi6D+seiK\n" +
            "yyd0Jfgeop1/ZHwAGgpKQNvOJBVKqiIgcQ1HMKD+/NK1EPa2KqecNw/9I+e33mWU\n" +
            "IZzWCHEptA/yc832e+/SemwhhTUBjIvEGL6NfpUkHr+HU/2yzYXe+1J3LVYGFlgu\n" +
            "t78E3cx+oAXCEZcV1Rj8A+GgVt6njZ/Im/RMRbo2MRu1fsNmMtblMtZu7rRiOy+w\n" +
            "+wAR4fzJHYBgC1DpXLtQfIvNa3dVTDzcyI4ZSSavA1+jKY1E56dqzVAxUqpC08JO\n" +
            "Iespiiwpu8czdIVF2LX8bv83uqyueVPQiaBCgkochrDVu1FErxqU0FmiaTYvpz8D\n" +
            "Tg==\n" +
            "-----END CERTIFICATE-----";
        subject.setCertificate(certificate);

        assertThat(subject.getKeyUsage().hasUsages(KeyUsage.digitalSignature | KeyUsage.keyAgreement), equalTo(true));
        assertThat(subject.getKeyUsage().hasUsages(KeyUsage.digitalSignature | KeyUsage.encipherOnly), equalTo(false));

        assertThat(Arrays.asList(subject.getExtendedKeyUsage().getUsages()), containsInAnyOrder(KeyPurposeId.id_kp_codeSigning, KeyPurposeId.id_kp_emailProtection));
      });
    });

    describe("#copyInto", () -> {
      it("should copy the correct values", () -> {
        Instant frozenTime = Instant.ofEpochSecond(1400000000L);
        UUID uuid = UUID.randomUUID();
        UUID encryptionKeyUuid = UUID.randomUUID();

        subject = new NamedCertificateSecret("name");
        subject.setCa("fake-ca");
        subject.setCertificate("fake-certificate");
        subject.setPrivateKey("fake-private-key");
        subject.setCaName("ca-name");
        subject.setUuid(uuid);
        subject.setUpdatedAt(frozenTime);
        subject.setEncryptionKeyUuid(encryptionKeyUuid);

        NamedCertificateSecret copy = new NamedCertificateSecret();
        subject.copyInto(copy);

        assertThat(copy.getName(), equalTo("name"));
        assertThat(copy.getCaName(), equalTo("ca-name"));
        assertThat(copy.getCa(), equalTo("fake-ca"));
        assertThat(copy.getPrivateKey(), equalTo("fake-private-key"));
        assertThat(copy.getEncryptionKeyUuid(), equalTo(encryptionKeyUuid));

        assertThat(copy.getUuid(), not(equalTo(uuid)));
        assertThat(copy.getUpdatedAt(), not(equalTo(frozenTime)));
      });
    });
  }
}
