package org.cloudfoundry.credhub.handlers;

import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.audit.entities.BulkRegenerateCredential;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.generate.GenerationRequestGenerator;
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator;
import org.cloudfoundry.credhub.regenerate.DefaultRegenerateHandler;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest;
import org.cloudfoundry.credhub.requests.PasswordGenerateRequest;
import org.cloudfoundry.credhub.services.DefaultCredentialService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.cloudfoundry.credhub.views.BulkRegenerateResults;
import org.cloudfoundry.credhub.views.CertificateValueView;
import org.cloudfoundry.credhub.views.CredentialView;
import org.hamcrest.MatcherAssert;
import org.hamcrest.core.IsEqual;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions .fail;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_CA;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_TRUSTED_CA;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isOneOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.hamcrest.MockitoHamcrest.argThat;
import static org.mockito.internal.verification.VerificationModeFactory.times;


@RunWith(JUnit4.class)
public class DefaultRegenerateHandlerTest {

  private static final String SIGNER_NAME = "/signer_name";
  private static final String CREDENTIAL_NAME = "/credName";
  private static final String USER = "darth-sirius";


  private DefaultRegenerateHandler subjectWithAclsEnabled;
  private DefaultRegenerateHandler subjectWithAclsDisabled;
  private DefaultRegenerateHandler subjectWithConcatenateCasEnabled;
  private DefaultRegenerateHandler subjectWithconcatenateCasDisabled;
  private DefaultCredentialService credentialService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private CredentialVersion credentialVersion;
  private CEFAuditRecord cefAuditRecord;
  private CredentialValue credValue;
  private PermissionCheckingService permissionCheckingService;

  @BeforeClass
  public static void setUpAll() {
    BouncyCastleFipsConfigurer.configure();
  }
  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }
    credentialService = mock(DefaultCredentialService.class);
    credentialGenerator = mock(UniversalCredentialGenerator.class);
    generationRequestGenerator = mock(GenerationRequestGenerator.class);
    credentialVersion = mock(PasswordCredentialVersion.class);
    cefAuditRecord = mock(CEFAuditRecord.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    UserContextHolder userContextHolder = mock(UserContextHolder.class);
    credValue = new StringCredentialValue("secret");
    subjectWithAclsEnabled = new DefaultRegenerateHandler(
      credentialService,
      credentialGenerator,
      generationRequestGenerator,
      cefAuditRecord,
      permissionCheckingService,
      userContextHolder,
      true,
      false
      );
    subjectWithAclsDisabled = new DefaultRegenerateHandler(
      credentialService,
      credentialGenerator,
      generationRequestGenerator,
      cefAuditRecord,
      permissionCheckingService,
      userContextHolder,
      false,
      false
      );
    subjectWithconcatenateCasDisabled = new DefaultRegenerateHandler(
      credentialService,
      credentialGenerator,
      generationRequestGenerator,
      cefAuditRecord,
      permissionCheckingService,
      userContextHolder,
      false,
      false
    );
    subjectWithConcatenateCasEnabled = new DefaultRegenerateHandler(
      credentialService,
      credentialGenerator,
      generationRequestGenerator,
      cefAuditRecord,
      permissionCheckingService,
      userContextHolder,
      false,
      true
    );

    UserContext userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(USER);
    when(userContextHolder.getUserContext()).thenReturn(userContext);
  }

  @Test
  public void handleRegenerate_addsToAuditRecord() {
    final BaseCredentialGenerateRequest request = new PasswordGenerateRequest();
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);
    when(credentialVersion.getCredential()).thenReturn(mock(Credential.class));
    when(((PasswordCredentialVersion) credentialVersion).getPassword()).thenReturn("password");
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion);
    when(generationRequestGenerator.createGenerateRequest(credentialVersion))
      .thenReturn(request);
    when(credentialGenerator.generate(request)).thenReturn(credValue);
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);

    subjectWithAclsEnabled.handleRegenerate(CREDENTIAL_NAME, null);

    verify(cefAuditRecord, times(1)).setVersion(any(CredentialVersion.class));
    verify(cefAuditRecord, times(1)).setResource(any(Credential.class));
  }

  @Test
  public void handleRegenerate_whenUserHasPermission_andAclsEnabled_regeneratesCredential() {
    final CredentialVersion existingCredentialVersion = mock(CertificateCredentialVersion.class);
    when(existingCredentialVersion.getName()).thenReturn("existing version");
    final CredentialVersion savedCredentialVersion = mock(CertificateCredentialVersion.class);
    when(savedCredentialVersion.getName()).thenReturn("saved version");

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    when(generateRequest1.getName()).thenReturn("/firstExpectedName");

    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion))
      .thenReturn(generateRequest1);
    when(credentialGenerator.generate(generateRequest1))
      .thenReturn(credValue);
    when(credentialService.save(existingCredentialVersion, credValue, generateRequest1))
      .thenReturn(savedCredentialVersion);

    CredentialView actualCredentialView = subjectWithAclsEnabled.handleRegenerate(CREDENTIAL_NAME, null);
    CredentialView expectedCredentialView = CredentialView.fromEntity(savedCredentialVersion, false, true);

    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    assertThat(actualCredentialView).isEqualTo(expectedCredentialView);
  }

  @Test
  public void handleRegenerate_whenConcatenateCasIsEnabled_regeneratesTheCredentialWithConcatenatedCas() {
    final CertificateCredentialVersion existingCredentialVersion = mock(CertificateCredentialVersion.class);
    final CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    final CertificateCredentialValue credentialValue = mock(CertificateCredentialValue.class);
    final CertificateCredentialVersion credentialVersion = mock(CertificateCredentialVersion.class);


    when(existingCredentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    when(credentialValue.getCa()).thenReturn(TEST_CA);
    when(credentialValue.getTrustedCa()).thenReturn(TestConstants.TEST_TRUSTED_CA);

    when(credentialVersion.getCa()).thenReturn(TEST_CA);
    when(credentialVersion.getTrustedCa()).thenReturn(TestConstants.TEST_TRUSTED_CA);
    when(credentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialVersion.getUuid()).thenReturn(UUID.randomUUID());

    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion)).thenReturn(generateRequest);
    when(credentialGenerator.generate(generateRequest)).thenReturn(credentialValue);
    when(credentialService.save(existingCredentialVersion, credentialValue, generateRequest))
      .thenReturn(credentialVersion);

    CredentialView actualCredentialView = subjectWithConcatenateCasEnabled.handleRegenerate(CREDENTIAL_NAME, null);

    assertThat(((CertificateValueView) actualCredentialView.getValue()).getCa())
      .isEqualTo(TEST_CA + "\n" + TEST_TRUSTED_CA + "\n");
  }

  @Test
  public void handleRegenerate_whenConcatenateCasIsDisabled_regeneratesTheCredentialWithoutConcatenatedCas() {
    final CertificateCredentialVersion existingCredentialVersion = mock(CertificateCredentialVersion.class);
    when(existingCredentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    final CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    final CertificateCredentialValue credentialValue = mock(CertificateCredentialValue.class);
    when(credentialValue.getCa()).thenReturn(TEST_CA);
    when(credentialValue.getTrustedCa()).thenReturn(TestConstants.TEST_TRUSTED_CA);

    final CertificateCredentialVersion credentialVersion = mock(CertificateCredentialVersion.class);
    when(credentialVersion.getCa()).thenReturn(TEST_CA);
    when(credentialVersion.getTrustedCa()).thenReturn(TestConstants.TEST_TRUSTED_CA);
    when(credentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialVersion.getUuid()).thenReturn(UUID.randomUUID());

    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion)).thenReturn(generateRequest);
    when(credentialGenerator.generate(generateRequest)).thenReturn(credentialValue);
    when(credentialService.save(existingCredentialVersion, credentialValue, generateRequest))
      .thenReturn(credentialVersion);


    CredentialView actualCredentialView = subjectWithconcatenateCasDisabled.handleRegenerate(CREDENTIAL_NAME, null);

    verify(credentialValue, never()).setCa(any());
    assertThat(((CertificateValueView) actualCredentialView.getValue()).getCa())
      .isEqualTo(TEST_CA);
  }

  @Test
  public void handleRegenerate_whenUserLacksPermission_andAclsEnabled_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAclsEnabled.handleRegenerate(CREDENTIAL_NAME, null);
      fail("should throw exception");
    } catch (final PermissionException e) {
      MatcherAssert.assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    } catch (final Exception e) {
      fail("expected EntryNotFoundException but got " + e.getClass().toString());
    }

    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
  }

  @Test
  public void handleRegenerate_whenAclsAreDisabled_regeneratesCredential() {
    final CredentialVersion existingCredentialVersion = mock(CertificateCredentialVersion.class);
    when(existingCredentialVersion.getName()).thenReturn("existing version");
    final CredentialVersion savedCredentialVersion = mock(CertificateCredentialVersion.class);
    when(savedCredentialVersion.getName()).thenReturn("saved version");

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    when(generateRequest1.getName()).thenReturn("/firstExpectedName");

    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion))
      .thenReturn(generateRequest1);
    when(credentialGenerator.generate(generateRequest1))
      .thenReturn(credValue);
    when(credentialService.save(existingCredentialVersion, credValue, generateRequest1))
      .thenReturn(savedCredentialVersion);

    CredentialView actualCredentialView = subjectWithAclsDisabled.handleRegenerate(CREDENTIAL_NAME, null);
    CredentialView expectedCredentialView = CredentialView.fromEntity(savedCredentialVersion, false, true);

    verify(permissionCheckingService, times(0)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    assertThat(actualCredentialView).isEqualTo(expectedCredentialView);
  }

  @Test
  public void handleBulkRegenerate_addsToAuditRecord() {
    final String signedBy = "fooCA";
    final List<String> certificateCredentials = Arrays.asList("foo", "bar", "baz");
    final CredentialVersion credVersion = new CertificateCredentialVersion("some-name");
    credVersion.setCredential(new Credential("foo"));
    final BulkRegenerateCredential bulkRegenerateCredential = new BulkRegenerateCredential(signedBy);

    when(credentialService.findAllCertificateCredentialsByCaName(signedBy)).thenReturn(certificateCredentials);

    final CertificateGenerateRequest request = spy(CertificateGenerateRequest.class);
    request.setName("test");
    when(credentialService.findMostRecent(argThat(isOneOf("foo", "bar", "baz")))).thenReturn(credVersion);
    when(generationRequestGenerator.createGenerateRequest(argThat(is(credVersion)))).thenReturn(request);
    when(credentialGenerator.generate(request)).thenReturn(credValue);

    when(credentialService.save(credVersion, credValue, request)).thenReturn(credVersion);

    final CertificateGenerationParameters generationParams = mock(CertificateGenerationParameters.class);
    when(generationParams.isCa()).thenReturn(true);
    request.setCertificateGenerationParameters(generationParams);
    when(request.getGenerationParameters()).thenReturn(generationParams);

    subjectWithAclsDisabled.handleBulkRegenerate(signedBy);
    verify(cefAuditRecord, times(1)).setRequestDetails(bulkRegenerateCredential);
    verify(cefAuditRecord, times(certificateCredentials.size())).addVersion(any(CredentialVersion.class));
    verify(cefAuditRecord, times(certificateCredentials.size())).addResource(any(Credential.class));
  }

  @Test
  public void handleBulkRegenerate_whenUserHasPermission_andAclsEnabled_regeneratesEverythingInTheListRecursively() {
    final String firstExpectedName = "/firstExpectedName";
    final String secondExpectedName = "/secondExpectedName";
    final String thirdExpectedName = "/thirdExpectedName";
    final String fourthExpectedName = "/fourthExpectedName";

    CertificateCredentialVersion existingCredentialVersion1 = new CertificateCredentialVersion(firstExpectedName);
    existingCredentialVersion1.setCertificate(TEST_CA);
    CertificateCredentialVersion existingCredentialVersion2 = new CertificateCredentialVersion(secondExpectedName);
    existingCredentialVersion2.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion existingCredentialVersion3 = new CertificateCredentialVersion(thirdExpectedName);
    existingCredentialVersion3.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion existingCredentialVersion4 = new CertificateCredentialVersion(fourthExpectedName);
    existingCredentialVersion4.setCertificate(TestConstants.TEST_CERTIFICATE);

    CertificateCredentialVersion savedCredentialVersion1 = new CertificateCredentialVersion(firstExpectedName);
    savedCredentialVersion1.setCertificate(TEST_CA);
    CertificateCredentialVersion savedCredentialVersion2 = new CertificateCredentialVersion(secondExpectedName);
    savedCredentialVersion2.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion savedCredentialVersion3 = new CertificateCredentialVersion(thirdExpectedName);
    savedCredentialVersion3.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion savedCredentialVersion4 = new CertificateCredentialVersion(fourthExpectedName);
    savedCredentialVersion4.setCertificate(TestConstants.TEST_CERTIFICATE);

    when(credentialService.findAllCertificateCredentialsByCaName(SIGNER_NAME))
      .thenReturn(newArrayList(firstExpectedName, secondExpectedName));

    when(credentialService.findAllCertificateCredentialsByCaName(firstExpectedName))
      .thenReturn(newArrayList(thirdExpectedName, fourthExpectedName));

    when(credentialService.findMostRecent(firstExpectedName))
      .thenReturn(existingCredentialVersion1);
    when(credentialService.findMostRecent(secondExpectedName))
      .thenReturn(existingCredentialVersion2);
    when(credentialService.findMostRecent(thirdExpectedName))
      .thenReturn(existingCredentialVersion3);
    when(credentialService.findMostRecent(fourthExpectedName))
      .thenReturn(existingCredentialVersion4);

    when(permissionCheckingService.hasPermission(USER, SIGNER_NAME, PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, firstExpectedName, PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, firstExpectedName, PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, thirdExpectedName, PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, fourthExpectedName, PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, secondExpectedName, PermissionOperation.WRITE))
      .thenReturn(true);

    when(credentialService.save(eq(existingCredentialVersion1), any(), any())).thenReturn(savedCredentialVersion1);
    when(credentialService.save(eq(existingCredentialVersion2), any(), any())).thenReturn(savedCredentialVersion2);
    when(credentialService.save(eq(existingCredentialVersion3), any(), any())).thenReturn(savedCredentialVersion3);
    when(credentialService.save(eq(existingCredentialVersion4), any(), any())).thenReturn(savedCredentialVersion4);

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    generateRequest1.setName(firstExpectedName);
    when(generateRequest1.getName()).thenReturn(firstExpectedName);
    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    final CertificateGenerateRequest generateRequest2 = mock(CertificateGenerateRequest.class);
    when(generateRequest2.getName()).thenReturn(secondExpectedName);
    final CertificateGenerationParameters generationParams2 = mock(CertificateGenerationParameters.class);
    when(generationParams2.isCa()).thenReturn(false);
    when(generateRequest2.getGenerationParameters()).thenReturn(generationParams2);

    final CertificateGenerateRequest generateRequest3 = mock(CertificateGenerateRequest.class);
    when(generateRequest3.getName()).thenReturn(thirdExpectedName);
    final CertificateGenerationParameters generationParams3 = mock(CertificateGenerationParameters.class);
    when(generationParams3.isCa()).thenReturn(false);
    when(generateRequest3.getGenerationParameters()).thenReturn(generationParams3);

    final CertificateGenerateRequest generateRequest4 = mock(CertificateGenerateRequest.class);
    when(generateRequest4.getName()).thenReturn(fourthExpectedName);
    final CertificateGenerationParameters generationParams4 = mock(CertificateGenerationParameters.class);
    when(generationParams4.isCa()).thenReturn(false);
    when(generateRequest4.getGenerationParameters()).thenReturn(generationParams4);

    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion1)).thenReturn(generateRequest1);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion2)).thenReturn(generateRequest2);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion3)).thenReturn(generateRequest3);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion4)).thenReturn(generateRequest4);

    final BulkRegenerateResults bulkRegenerateResults = subjectWithAclsEnabled.handleBulkRegenerate(SIGNER_NAME);

    Set<String> regeneratedCredentials = bulkRegenerateResults.getRegeneratedCredentials();
    assertThat(regeneratedCredentials.size()).isEqualTo(4);
    assertThat(regeneratedCredentials.contains(firstExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(secondExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(thirdExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(fourthExpectedName)).isTrue();

    verify(permissionCheckingService, times(1)).hasPermission(USER, SIGNER_NAME, PermissionOperation.READ);
    verify(permissionCheckingService, times(1)).hasPermission(USER, firstExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1)).hasPermission(USER, firstExpectedName, PermissionOperation.READ);
    verify(permissionCheckingService, times(1)).hasPermission(USER, secondExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1)).hasPermission(USER, thirdExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1)).hasPermission(USER, fourthExpectedName, PermissionOperation.WRITE);
    verify(credentialService).save(eq(existingCredentialVersion1), any(), eq(generateRequest1));
    verify(credentialService).save(eq(existingCredentialVersion2), any(), eq(generateRequest2));
    verify(credentialService).save(eq(existingCredentialVersion3), any(), eq(generateRequest3));
    verify(credentialService).save(eq(existingCredentialVersion4), any(), eq(generateRequest4));
  }

  @Test
  public void handleBulkRegenerate_whenLacksPermission_andAclsEnabled_throwsException() {
    CertificateCredentialVersion credentialVersion1 = new CertificateCredentialVersion("some-name");
    credentialVersion1.setCertificate(TEST_CA);
    CertificateCredentialVersion credentialVersion2 = new CertificateCredentialVersion("some-name");
    credentialVersion2.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion credentialVersion3 = new CertificateCredentialVersion("some-name");
    credentialVersion3.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion credentialVersion4 = new CertificateCredentialVersion("some-name");
    credentialVersion4.setCertificate(TestConstants.TEST_CERTIFICATE);

    when(credentialService.findAllCertificateCredentialsByCaName(SIGNER_NAME))
      .thenReturn(newArrayList("/firstExpectedName", "/secondExpectedName"));
    when(credentialService.findAllCertificateCredentialsByCaName("/firstExpectedName"))
      .thenReturn(newArrayList("/thirdExpectedName", "/fourthExpectedName"));
    when(credentialService.findMostRecent("/firstExpectedName"))
      .thenReturn(credentialVersion1);
    when(credentialService.findMostRecent("/secondExpectedName"))
      .thenReturn(credentialVersion2);
    when(credentialService.findMostRecent("/thirdExpectedName"))
      .thenReturn(credentialVersion3);
    when(credentialService.findMostRecent("/fourthExpectedName"))
      .thenReturn(credentialVersion4);

    when(permissionCheckingService.hasPermission(USER, SIGNER_NAME, PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/firstExpectedName", PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/firstExpectedName", PermissionOperation.READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/thirdExpectedName", PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, "/fourthExpectedName", PermissionOperation.WRITE))
      .thenReturn(false);
    when(permissionCheckingService.hasPermission(USER, "/secondExpectedName", PermissionOperation.WRITE))
      .thenReturn(true);

    try {
      subjectWithAclsEnabled.handleBulkRegenerate(SIGNER_NAME);
      fail("should throw exception");
    } catch (final PermissionException e) {
      MatcherAssert.assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    } catch (final Exception e) {
      fail("expected EntryNotFoundException but got " + e.getClass().toString() + "\n" + Arrays.toString(e.getStackTrace()));
    }

    verify(credentialService, times(0)).save(any(), any(), any());
    verify(permissionCheckingService, times(1))
      .hasPermission(USER, SIGNER_NAME, PermissionOperation.READ);
    verify(permissionCheckingService, times(1))
      .hasPermission(USER, "/firstExpectedName", PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1))
      .hasPermission(USER, "/firstExpectedName", PermissionOperation.READ);
    verify(permissionCheckingService, times(1))
      .hasPermission(USER, "/thirdExpectedName", PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1))
      .hasPermission(USER, "/fourthExpectedName", PermissionOperation.WRITE);
    verify(permissionCheckingService, times(0))
      .hasPermission(USER, "/secondExpectedName", PermissionOperation.WRITE);

  }

  @Test
  public void handleBulkRegenerate_andAclsDisabled_regeneratesEverythingInTheListRecursively() {
    final String firstExpectedName = "/firstExpectedName";
    final String secondExpectedName = "/secondExpectedName";
    final String thirdExpectedName = "/thirdExpectedName";
    final String fourthExpectedName = "/fourthExpectedName";

    CertificateCredentialVersion existingCredentialVersion1 = new CertificateCredentialVersion(firstExpectedName);
    existingCredentialVersion1.setCertificate(TEST_CA);
    CertificateCredentialVersion existingCredentialVersion2 = new CertificateCredentialVersion(secondExpectedName);
    existingCredentialVersion2.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion existingCredentialVersion3 = new CertificateCredentialVersion(thirdExpectedName);
    existingCredentialVersion3.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion existingCredentialVersion4 = new CertificateCredentialVersion(fourthExpectedName);
    existingCredentialVersion4.setCertificate(TestConstants.TEST_CERTIFICATE);

    CertificateCredentialVersion savedCredentialVersion1 = new CertificateCredentialVersion(firstExpectedName);
    savedCredentialVersion1.setCertificate(TEST_CA);
    CertificateCredentialVersion savedCredentialVersion2 = new CertificateCredentialVersion(secondExpectedName);
    savedCredentialVersion2.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion savedCredentialVersion3 = new CertificateCredentialVersion(thirdExpectedName);
    savedCredentialVersion3.setCertificate(TestConstants.TEST_CERTIFICATE);
    CertificateCredentialVersion savedCredentialVersion4 = new CertificateCredentialVersion(fourthExpectedName);
    savedCredentialVersion4.setCertificate(TestConstants.TEST_CERTIFICATE);

    when(credentialService.findAllCertificateCredentialsByCaName(SIGNER_NAME))
      .thenReturn(newArrayList(firstExpectedName, secondExpectedName));

    when(credentialService.findAllCertificateCredentialsByCaName(firstExpectedName))
      .thenReturn(newArrayList(thirdExpectedName, fourthExpectedName));

    when(credentialService.findMostRecent(firstExpectedName))
      .thenReturn(existingCredentialVersion1);
    when(credentialService.findMostRecent(secondExpectedName))
      .thenReturn(existingCredentialVersion2);
    when(credentialService.findMostRecent(thirdExpectedName))
      .thenReturn(existingCredentialVersion3);
    when(credentialService.findMostRecent(fourthExpectedName))
      .thenReturn(existingCredentialVersion4);

    when(credentialService.save(eq(existingCredentialVersion1), any(), any())).thenReturn(savedCredentialVersion1);
    when(credentialService.save(eq(existingCredentialVersion2), any(), any())).thenReturn(savedCredentialVersion2);
    when(credentialService.save(eq(existingCredentialVersion3), any(), any())).thenReturn(savedCredentialVersion3);
    when(credentialService.save(eq(existingCredentialVersion4), any(), any())).thenReturn(savedCredentialVersion4);

    final CertificateGenerateRequest generateRequest1 = mock(CertificateGenerateRequest.class);
    generateRequest1.setName(firstExpectedName);
    when(generateRequest1.getName()).thenReturn(firstExpectedName);
    final CertificateGenerationParameters generationParams1 = mock(CertificateGenerationParameters.class);
    when(generationParams1.isCa()).thenReturn(true);
    when(generateRequest1.getGenerationParameters()).thenReturn(generationParams1);

    final CertificateGenerateRequest generateRequest2 = mock(CertificateGenerateRequest.class);
    when(generateRequest2.getName()).thenReturn(secondExpectedName);
    final CertificateGenerationParameters generationParams2 = mock(CertificateGenerationParameters.class);
    when(generationParams2.isCa()).thenReturn(false);
    when(generateRequest2.getGenerationParameters()).thenReturn(generationParams2);

    final CertificateGenerateRequest generateRequest3 = mock(CertificateGenerateRequest.class);
    when(generateRequest3.getName()).thenReturn(thirdExpectedName);
    final CertificateGenerationParameters generationParams3 = mock(CertificateGenerationParameters.class);
    when(generationParams3.isCa()).thenReturn(false);
    when(generateRequest3.getGenerationParameters()).thenReturn(generationParams3);

    final CertificateGenerateRequest generateRequest4 = mock(CertificateGenerateRequest.class);
    when(generateRequest4.getName()).thenReturn(fourthExpectedName);
    final CertificateGenerationParameters generationParams4 = mock(CertificateGenerationParameters.class);
    when(generationParams4.isCa()).thenReturn(false);
    when(generateRequest4.getGenerationParameters()).thenReturn(generationParams4);

    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion1)).thenReturn(generateRequest1);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion2)).thenReturn(generateRequest2);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion3)).thenReturn(generateRequest3);
    when(generationRequestGenerator.createGenerateRequest(existingCredentialVersion4)).thenReturn(generateRequest4);

    final BulkRegenerateResults bulkRegenerateResults = subjectWithAclsDisabled.handleBulkRegenerate(SIGNER_NAME);

    Set<String> regeneratedCredentials = bulkRegenerateResults.getRegeneratedCredentials();
    assertThat(regeneratedCredentials.size()).isEqualTo(4);
    assertThat(regeneratedCredentials.contains(firstExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(secondExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(thirdExpectedName)).isTrue();
    assertThat(regeneratedCredentials.contains(fourthExpectedName)).isTrue();

    verify(permissionCheckingService, times(0)).hasPermission(USER, SIGNER_NAME, PermissionOperation.READ);
    verify(permissionCheckingService, times(0)).hasPermission(USER, firstExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(0)).hasPermission(USER, firstExpectedName, PermissionOperation.READ);
    verify(permissionCheckingService, times(0)).hasPermission(USER, secondExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(0)).hasPermission(USER, thirdExpectedName, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(0)).hasPermission(USER, fourthExpectedName, PermissionOperation.WRITE);
    verify(credentialService, times(2)).findAllCertificateCredentialsByCaName(any());
    verify(credentialService).save(eq(existingCredentialVersion1), any(), eq(generateRequest1));
    verify(credentialService).save(eq(existingCredentialVersion2), any(), eq(generateRequest2));
    verify(credentialService).save(eq(existingCredentialVersion3), any(), eq(generateRequest3));
    verify(credentialService).save(eq(existingCredentialVersion4), any(), eq(generateRequest4));
  }

  @Test
  public void handleRegenerate_whenRegeneratingCertificate_andCanNotReadCa_throwsException() {
    CertificateCredentialVersion credentialVersion = new CertificateCredentialVersion(CREDENTIAL_NAME);
    credentialVersion.setCertificate(TestConstants.TEST_CERTIFICATE);
    credentialVersion.setCaName(SIGNER_NAME);

    final CertificateGenerateRequest generateRequest = mock(CertificateGenerateRequest.class);
    generateRequest.setName(CREDENTIAL_NAME);
    when(generateRequest.getName()).thenReturn(CREDENTIAL_NAME);
    final CertificateGenerationParameters generationParams = mock(CertificateGenerationParameters.class);
    when(generationParams.isCa()).thenReturn(false);
    when(generateRequest.getGenerationParameters()).thenReturn(generationParams);

    when(generationRequestGenerator.createGenerateRequest(credentialVersion)).thenReturn(generateRequest);
    when(credentialService.findMostRecent(CREDENTIAL_NAME))
      .thenReturn(credentialVersion);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, SIGNER_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAclsEnabled.handleRegenerate(CREDENTIAL_NAME, null);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      MatcherAssert.assertThat(e.getMessage(), IsEqual.equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    } catch (final Exception e) {
      fail("expected EntryNotFoundException but got " + e.getClass().toString() + "\n" + Arrays.toString(e.getStackTrace()));
    }


    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    verify(permissionCheckingService, times(1)).hasPermission(USER, SIGNER_NAME, PermissionOperation.READ);

  }

  @Test
  public void handleRegenerate_withMetadata() {
    final BaseCredentialGenerateRequest request = new PasswordGenerateRequest();
    when(((PasswordCredentialVersion) credentialVersion).getPassword()).thenReturn("password");
    when(credentialService.findMostRecent(CREDENTIAL_NAME)).thenReturn(credentialVersion);
    when(generationRequestGenerator.createGenerateRequest(credentialVersion))
            .thenReturn(request);
    when(credentialGenerator.generate(request)).thenReturn(credValue);
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);

    JsonNode metadata = null;
    try {
      metadata = new ObjectMapper().readTree("{\"some\":\"metadata example\"}");
    } catch (Exception e) {
      fail(e.toString());
    }

    assertThat(metadata).isNotEmpty();

    CredentialView actualCredentialView = subjectWithAclsDisabled.handleRegenerate(CREDENTIAL_NAME, metadata);
    CredentialView expectedCredentialView = CredentialView.fromEntity(credentialVersion);

    assertThat(actualCredentialView).isEqualTo(expectedCredentialView);
  }
}
