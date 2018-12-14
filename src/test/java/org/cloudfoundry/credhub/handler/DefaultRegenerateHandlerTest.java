package org.cloudfoundry.credhub.handler;

import java.util.Arrays;
import java.util.List;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entity.BulkRegenerateCredential;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.request.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.request.CertificateGenerateRequest;
import org.cloudfoundry.credhub.request.PasswordGenerateRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static com.google.common.collect.Lists.newArrayList;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;
import static org.mockito.internal.verification.VerificationModeFactory.times;


@RunWith(JUnit4.class)
public class DefaultRegenerateHandlerTest {

  private static final String SIGNER_NAME = "signer name";
  private static final String CREDENTIAL_NAME = "credName";

  private DefaultRegenerateHandler subject;
  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CredentialVersion credentialVersion;
  private CEFAuditRecord cefAuditRecord;
  private CredentialValue credValue;

  @Before
  public void beforeEach() {
    credentialService = mock(PermissionedCredentialService.class);
    credentialGenerator = mock(UniversalCredentialGenerator.class);
    generationRequestGenerator = mock(GenerationRequestGenerator.class);
    credentialVersion = mock(PasswordCredentialVersion.class);
    cefAuditRecord = mock(CEFAuditRecord.class);
    credValue = new StringCredentialValue("secret");
    subject = new DefaultRegenerateHandler(
      credentialService,
      credentialGenerator,
      generationRequestGenerator,
      cefAuditRecord
    );
  }

  @Test
  public void handleRegenerate_addsToAuditRecord() {
    final BaseCredentialGenerateRequest request = new PasswordGenerateRequest();
    when(credentialVersion.getCredential()).thenReturn(mock(Credential.class));
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion);
    when(generationRequestGenerator.createGenerateRequest(credentialVersion))
      .thenReturn(request);
    when(credentialGenerator.generate(request)).thenReturn(credValue);
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);

    subject.handleRegenerate(CREDENTIAL_NAME);

    verify(cefAuditRecord, times(1)).setVersion(any(CredentialVersion.class));
    verify(cefAuditRecord, times(1)).setResource(any(Credential.class));
  }

  @Test
  public void handleBulkRegenerate_addsToAuditRecord() {
    final String signedBy = "fooCA";
    final List<String> certificateCredentials = Arrays.asList("foo", "bar", "baz");
    final CredentialVersion credVersion = new CertificateCredentialVersion();
    credVersion.setCredential(new Credential("foo"));
    final BulkRegenerateCredential bulkRegenerateCredential = new BulkRegenerateCredential(signedBy);

    when(credentialService.findAllCertificateCredentialsByCaName(signedBy)).thenReturn(certificateCredentials);

    final CertificateGenerateRequest request = spy(CertificateGenerateRequest.class);
    when(credentialService.findMostRecent(argThat(isOneOf("foo", "bar", "baz")))).thenReturn(credVersion);
    when(generationRequestGenerator.createGenerateRequest(argThat(is(credVersion)))).thenReturn(request);
    when(credentialGenerator.generate(request)).thenReturn(credValue);

    when(credentialService.save(credVersion, credValue, request)).thenReturn(credVersion);

    final CertificateGenerationParameters generationParams = mock(CertificateGenerationParameters.class);
    when(generationParams.isCa()).thenReturn(true);
    request.setCertificateGenerationParameters(generationParams);
    when(request.getGenerationParameters()).thenReturn(generationParams);

    subject.handleBulkRegenerate(signedBy);
    verify(cefAuditRecord, times(1)).setRequestDetails(bulkRegenerateCredential);
    verify(cefAuditRecord, times(certificateCredentials.size())).addVersion(any(CredentialVersion.class));
    verify(cefAuditRecord, times(certificateCredentials.size())).addResource(any(Credential.class));
  }

  @Test
  public void handleBulkRegenerate_regeneratesEverythingInTheList() {
    when(credentialService.findAllCertificateCredentialsByCaName(SIGNER_NAME))
      .thenReturn(newArrayList("firstExpectedName", "secondExpectedName"));
    when(credentialService.findMostRecent(anyString()))
      .thenReturn(mock(CredentialVersion.class));
    final CredentialVersion credentialVersion = mock(CertificateCredentialVersion.class);
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);
    when(credentialVersion.getName()).thenReturn("someName");

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    generateRequest1.setName("/firstExpectedName");
    when(generateRequest1.getName()).thenReturn("/firstExpectedName");
    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    final CertificateGenerateRequest generateRequest2 = mock(CertificateGenerateRequest.class);
    when(generateRequest2.getName()).thenReturn("/secondExpectedName");
    final CertificateGenerationParameters generationParams2 = mock(CertificateGenerationParameters.class);
    when(generationParams2.isCa()).thenReturn(false);
    when(generateRequest2.getGenerationParameters()).thenReturn(generationParams2);

    when(generationRequestGenerator.createGenerateRequest(any(CredentialVersion.class)))
      .thenReturn(generateRequest1)
      .thenReturn(generateRequest2);

    subject.handleBulkRegenerate(SIGNER_NAME);

    verify(credentialService).save(any(), any(), eq(generateRequest1));
    verify(credentialService).save(any(), any(), eq(generateRequest2));
  }

  @Test
  public void handleBulkRegenerate_regeneratesToNestedLevels() {
    when(credentialService.findAllCertificateCredentialsByCaName(SIGNER_NAME))
      .thenReturn(newArrayList("/firstExpectedName", "/secondExpectedName"));
    when(credentialService.findAllCertificateCredentialsByCaName("/firstExpectedName"))
      .thenReturn(newArrayList("/thirdExpectedName", "/fourthExpectedName"));
    when(credentialService.findMostRecent(anyString()))
      .thenReturn(mock(CredentialVersion.class));

    final CredentialVersion credentialVersion = mock(CredentialVersion.class);
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);
    when(credentialVersion.getName()).thenReturn("placeholder");

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    when(generateRequest1.getName()).thenReturn("/firstExpectedName");
    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    final CertificateGenerateRequest generateRequest2 = mock(CertificateGenerateRequest.class);
    when(generateRequest2.getName()).thenReturn("/secondExpectedName");
    final CertificateGenerationParameters generationParams2 = mock(CertificateGenerationParameters.class);
    when(generationParams2.isCa()).thenReturn(false);
    when(generateRequest2.getGenerationParameters()).thenReturn(generationParams2);

    final CertificateGenerateRequest generateRequest3 = mock(CertificateGenerateRequest.class);
    when(generateRequest3.getName()).thenReturn("/thirdExpectedName");
    final CertificateGenerationParameters generationParams3 = mock(CertificateGenerationParameters.class);
    when(generationParams3.isCa()).thenReturn(false);
    when(generateRequest3.getGenerationParameters()).thenReturn(generationParams3);

    final CertificateGenerateRequest generateRequest4 = mock(CertificateGenerateRequest.class);
    when(generateRequest4.getName()).thenReturn("/fourthExpectedName");
    final CertificateGenerationParameters generationParams4 = mock(CertificateGenerationParameters.class);
    when(generationParams4.isCa()).thenReturn(false);
    when(generateRequest4.getGenerationParameters()).thenReturn(generationParams4);

    when(generationRequestGenerator.createGenerateRequest(any(CredentialVersion.class)))
      .thenReturn(generateRequest1)
      .thenReturn(generateRequest3)
      .thenReturn(generateRequest4)
      .thenReturn(generateRequest2);

    subject.handleBulkRegenerate(SIGNER_NAME);

    verify(credentialService).save(any(), any(), eq(generateRequest1));
    verify(credentialService).save(any(), any(), eq(generateRequest3));
    verify(credentialService).save(any(), any(), eq(generateRequest4));
    verify(credentialService).save(any(), any(), eq(generateRequest2));

  }

}
