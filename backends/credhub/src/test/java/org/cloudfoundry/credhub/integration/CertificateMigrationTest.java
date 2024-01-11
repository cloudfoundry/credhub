package org.cloudfoundry.credhub.integration;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.data.CertificateMigration;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repositories.CredentialRepository;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(SpringRunner.class)
@ActiveProfiles(
  value = {
    "unit-test",
    "unit-test-permissions",
  },
  resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredhubTestApp.class)
@Transactional
public class CertificateMigrationTest {

  @Autowired
  private CredentialVersionRepository credentialVersionRepository;

  @Autowired
  private CredentialRepository credentialRepository;

  @Autowired
  private CertificateMigration subject;

  @Test
  public void getCertificate_withNullExpiryDateInTheDatabase_andExpectExpiryDateAfterMigration() throws Exception {
    final String certificate = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDODCCAiCgAwIBAgIJAJHJbZB6doRCMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNV\n"
      + "BAMUEWNyZWRodWJfY2xpZW50X2NhMB4XDTE4MDgxNjE5MDMxMloXDTE5MDgxNjE5\n"
      + "MDMxMlowHDEaMBgGA1UEAxQRY3JlZGh1Yl9jbGllbnRfY2EwggEiMA0GCSqGSIb3\n"
      + "DQEBAQUAA4IBDwAwggEKAoIBAQDF/94LcAW/XRP2Dv4fZLP5j/PaeOAPItkgPFsu\n"
      + "Z+Td/2UyQvED/FW14rEMDLmb5Uf/tGI5gNdSJWE+aouedsNmFcYSY32mmImrZ6+O\n"
      + "p9Nzd7VNKv7u4nBKUPASDgU6Z6FJ1RfhSarYTA7icg1CqTI+1pP/Umg9wUUil28S\n"
      + "5c4v1v0sdz0/btkSgxZZ8e9Jx/578lYowjvxMWvauqzrz+Wl5YsNT2evin6asTGa\n"
      + "NMUHZW7rylhIWRh50gbrOspDiLVeDmwFeSxo7cVw4UtzNwCKDd5zxjmhbiJTA89o\n"
      + "RD+19jRGimI8/3a3EzrieOw8kXEfPoaQOWbMjDlvnXJ1CBEBAgMBAAGjfTB7MB0G\n"
      + "A1UdDgQWBBRTbSZK1FKzpEq4v4g9aOdHtt/3sTBMBgNVHSMERTBDgBRTbSZK1FKz\n"
      + "pEq4v4g9aOdHtt/3saEgpB4wHDEaMBgGA1UEAxQRY3JlZGh1Yl9jbGllbnRfY2GC\n"
      + "CQCRyW2QenaEQjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBRU5CN\n"
      + "2k2Esm2/Sy0Y+HdnJF255XfLNzATg6xMmw3h3g4Je8f2RISdvgeI1SINml0ZbbWw\n"
      + "GdNWLtROhLelxbfStm1e2lq9AxTUIS9kszioD/j02Ss7eaA7acMld6vLb1Rxfspv\n"
      + "/LmnboZ7A9iFXRVNdcXPmHsdnSERjIWJvLWDMrJjI4GL9ioe9xo5lKwTkC6crKc0\n"
      + "m49qs3YBgMLDJHicXSm3CHEqEbzrTckstwwHqDqYbug4nbOwna4ITiGeDW0gFuU/\n"
      + "dL+f0+UFGEkTYtR21PmOY5bnd0ZgVPCJrZ0WRHOdeh25toQ77Jdgo2OtiBJkJ3WE\n"
      + "6wiBnysQUOQO80Zw\n"
      + "-----END CERTIFICATE-----";

    final Credential credential = new Credential("test_credential");
    credentialRepository.save(credential);

    final CertificateCredentialVersionData versionData = new CertificateCredentialVersionData("test-ca");
    versionData.setTransitional(true);
    versionData.setCa("ca");
    versionData.setCaName("ca_name");
    versionData.setCertificate(certificate);
    versionData.setCredential(credential);

    final Instant expiryDate = new CertificateReader(certificate).getNotAfter();
    final CertificateCredentialVersionData originalVersion = credentialVersionRepository.save(versionData);

    assertThat(originalVersion.getExpiryDate(), is(equalTo(null)));

    subject.migrate();

    final CertificateCredentialVersionData migratedVersion =
      (CertificateCredentialVersionData) credentialVersionRepository.findOneByUuid(originalVersion.getUuid());

    assertThat(migratedVersion.getExpiryDate(), is(equalTo(expiryDate)));
  }

  @Test
  public void getCertificate_withNullCertificateAuthorityOrSelfSigned_andExpectCertificateAuthorityAndSelfSignedAfterMigration()
    throws Exception {
    final String certificate = TestConstants.TEST_CA;

    final Credential credential = new Credential("test_credential");
    credentialRepository.save(credential);

    final CertificateCredentialVersionData versionData = new CertificateCredentialVersionData("test-ca");
    versionData.setTransitional(true);
    versionData.setCa("ca");
    versionData.setCaName("ca_name");
    versionData.setCertificate(certificate);
    versionData.setCredential(credential);

    final CertificateCredentialVersionData originalVersion = credentialVersionRepository.save(versionData);

    assertThat(originalVersion.isCertificateAuthority(), is(equalTo(false)));
    assertThat(originalVersion.isSelfSigned(), is(equalTo(false)));

    subject.migrate();

    final CertificateCredentialVersionData migratedVersion =
      (CertificateCredentialVersionData) credentialVersionRepository.findOneByUuid(originalVersion.getUuid());

    assertThat(migratedVersion.isCertificateAuthority(), is(equalTo(true)));
    assertThat(migratedVersion.isSelfSigned(), is(equalTo(true)));
  }

  @Test
  public void getCertificate_WithInvalidCertFieldAndPrintsWarning() throws Exception {
    final String certificate = "-----BEGIN";

    final Credential credential = new Credential("test_malformed_credential");
    credentialRepository.save(credential);

    final CertificateCredentialVersionData versionData = new CertificateCredentialVersionData("test-ca");
    versionData.setTransitional(true);
    versionData.setCa("ca");
    versionData.setCaName("ca_name");
    versionData.setCertificate(certificate);
    versionData.setCredential(credential);

    credentialVersionRepository.save(versionData);

    subject.migrate();
  }

  @Test
  public void getCertificate_WithEmptyCertField_printsWarning() {
    final Credential credential = new Credential("test_empty_credential");
    credentialRepository.save(credential);

    final CertificateCredentialVersionData versionData = new CertificateCredentialVersionData("test-ca");
    versionData.setTransitional(true);
    versionData.setCa("ca");
    versionData.setCaName("ca_name");
    versionData.setCertificate(null);
    versionData.setCredential(credential);

    credentialVersionRepository.save(versionData);

    subject.migrate();
  }
}
