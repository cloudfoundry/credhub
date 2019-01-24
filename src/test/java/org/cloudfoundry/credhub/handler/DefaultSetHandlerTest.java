package org.cloudfoundry.credhub.handler;

import java.util.UUID;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.helper.TestHelper;
import org.cloudfoundry.credhub.request.CertificateSetRequest;
import org.cloudfoundry.credhub.request.PasswordSetRequest;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.request.UserSetRequest;
import org.cloudfoundry.credhub.service.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.util.TestConstants;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultSetHandlerTest {
  private DefaultPermissionedCredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;

  private DefaultSetHandler subject;

  private StringGenerationParameters generationParameters;
  private CredentialVersion credentialVersion;
  private UUID uuid;

  private CEFAuditRecord auditRecord;

  @Before
  public void setUp() {
    TestHelper.getBouncyCastleFipsProvider();
    credentialService = mock(DefaultPermissionedCredentialService.class);
    certificateAuthorityService = mock(CertificateAuthorityService.class);

    auditRecord = new CEFAuditRecord();
    subject = new DefaultSetHandler(credentialService, certificateAuthorityService, auditRecord);

    generationParameters = new StringGenerationParameters();
    credentialVersion = mock(PasswordCredentialVersion.class);

    uuid = UUID.randomUUID();
    final String name = "federation";

    final Credential cred = new Credential(name);
    cred.setUuid(uuid);

    when(credentialVersion.getCredential()).thenReturn(cred);
    when(credentialVersion.getName()).thenReturn(cred.getName());
    when(credentialVersion.getUuid()).thenReturn(cred.getUuid());
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);
  }

  @Test
  public void handleSetRequest_AddsTheCredentialNameToTheAuditRecord() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName("/captain");

    subject.handle(setRequest);

    verify(credentialService).save(null, password, setRequest);
    assertThat(auditRecord.getResourceName(), equalTo("federation"));
    assertThat(auditRecord.getResourceUUID(), equalTo(uuid.toString()));
    assertThat(auditRecord.getVersionUUID(), equalTo(credentialVersion.getUuid().toString()));
  }

  @Test
  public void handleSetRequest_whenPasswordSetRequest_passesCorrectParametersIncludingGeneration() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName("/captain");

    subject.handle(setRequest);

    verify(credentialService).save(null, password, setRequest);
  }

  @Test
  public void handleSetRequest_whenNonPasswordSetRequest_passesCorrectParametersWithNullGeneration() {
    final UserSetRequest setRequest = new UserSetRequest();
    final UserCredentialValue userCredentialValue = new UserCredentialValue(
      "Picard",
      "Enterprise",
      "salt");

    setRequest.setType("user");
    setRequest.setName("/captain");
    setRequest.setUserValue(userCredentialValue);

    subject.handle(setRequest);

    verify(credentialService).save(null, userCredentialValue, setRequest);
  }

  @Test
  public void handleSetRequest_withACertificateSetRequest_andNoCaName_usesCorrectParameters() {
    final CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue certificateValue = new CertificateCredentialValue(
      null,
      "Picard",
      "Enterprise",
      null);

    setRequest.setType("certificate");
    setRequest.setName("/captain");
    setRequest.setCertificateValue(certificateValue);

    subject.handle(setRequest);

    verify(credentialService).save(null, certificateValue, setRequest);
  }

  @Test
  public void handleSetRequest_withACertificateSetRequest_andACaName_providesCaCertificate() {
    final CertificateCredentialValue cerificateAuthority = new CertificateCredentialValue(
      null,
      TestConstants.TEST_CA,
      null,
      null
    );
    when(certificateAuthorityService.findActiveVersion("/test-ca-name"))
      .thenReturn(cerificateAuthority);

    final CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue credentialValue = new CertificateCredentialValue(
      null,
      TestConstants.TEST_CERTIFICATE,
      "Enterprise",
      "test-ca-name");

    setRequest.setType("certificate");
    setRequest.setName("/captain");
    setRequest.setCertificateValue(credentialValue);

    final CertificateCredentialValue expectedCredentialValue = new CertificateCredentialValue(
      TestConstants.TEST_CA,
      TestConstants.TEST_CERTIFICATE,
      "Enterprise",
      "/test-ca-name"
    );
    final ArgumentCaptor<CredentialValue> credentialValueArgumentCaptor = ArgumentCaptor.forClass(CredentialValue.class);

    subject.handle(setRequest);

    verify(credentialService).save(eq(null), credentialValueArgumentCaptor.capture(), eq(setRequest));
    assertThat(credentialValueArgumentCaptor.getValue(), samePropertyValuesAs(expectedCredentialValue));
  }
}
