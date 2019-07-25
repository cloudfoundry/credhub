package org.cloudfoundry.credhub.handlers;

import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.credentials.DefaultCredentialsHandler;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.generate.UniversalCredentialGenerator;
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.requests.CertificateSetRequest;
import org.cloudfoundry.credhub.requests.PasswordGenerateRequest;
import org.cloudfoundry.credhub.requests.PasswordSetRequest;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.requests.UserSetRequest;
import org.cloudfoundry.credhub.services.CertificateAuthorityService;
import org.cloudfoundry.credhub.services.DefaultCertificateAuthorityService;
import org.cloudfoundry.credhub.services.DefaultCredentialService;
import org.cloudfoundry.credhub.services.PermissionCheckingService;
import org.cloudfoundry.credhub.utils.TestConstants;
import org.cloudfoundry.credhub.views.CredentialView;
import org.cloudfoundry.credhub.views.DataResponse;
import org.cloudfoundry.credhub.views.FindCredentialResult;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import static com.google.common.collect.Lists.newArrayList;
import static java.util.Collections.EMPTY_SET;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DefaultCredentialsHandlerTest {
  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final Instant VERSION1_CREATED_AT = Instant.ofEpochMilli(555555555);
  private static final Instant VERSION2_CREATED_AT = Instant.ofEpochMilli(777777777);
  private static final String UUID_STRING = UUID.randomUUID().toString();
  private static final String USER = "darth-sirius";

  private DefaultCredentialsHandler subjectWithAcls;
  private DefaultCredentialsHandler subjectWithoutAcls;
  private DefaultCredentialService credentialService;
  private CEFAuditRecord auditRecord;
  private PermissionCheckingService permissionCheckingService;
  private CertificateAuthorityService certificateAuthorityService;

  private SshCredentialVersion version1;
  private SshCredentialVersion version2;
  private StringGenerationParameters generationParameters;
  private CredentialVersion credentialVersion;
  private UniversalCredentialGenerator universalCredentialGenerator;

  private Encryptor encryptor;

  @Before
  public void beforeEach() {
    TestHelper.getBouncyCastleFipsProvider();
    encryptor = mock(Encryptor.class);

    credentialService = mock(DefaultCredentialService.class);
    auditRecord = new CEFAuditRecord();
    permissionCheckingService = mock(PermissionCheckingService.class);
    UserContextHolder userContextHolder = mock(UserContextHolder.class);
    certificateAuthorityService = mock(DefaultCertificateAuthorityService.class);
    universalCredentialGenerator = mock(UniversalCredentialGenerator.class);

    subjectWithAcls = new DefaultCredentialsHandler(
      credentialService,
      auditRecord,
      permissionCheckingService,
      userContextHolder,
      certificateAuthorityService,
      universalCredentialGenerator,
      true,
      false);

    subjectWithoutAcls = new DefaultCredentialsHandler(
      credentialService,
      auditRecord,
      permissionCheckingService,
      userContextHolder,
      certificateAuthorityService,
      universalCredentialGenerator,
      false,
      false);


    generationParameters = new StringGenerationParameters();
    UserContext userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(USER);
    when(userContextHolder.getUserContext()).thenReturn(userContext);

    version1 = new SshCredentialVersion(CREDENTIAL_NAME);
    version1.setVersionCreatedAt(VERSION1_CREATED_AT);
    version1.setEncryptor(encryptor);
    version1.setUuid(UUID.randomUUID());
    version1.getCredential().setUuid(UUID.randomUUID());

    version2 = new SshCredentialVersion(CREDENTIAL_NAME);
    version2.setVersionCreatedAt(VERSION2_CREATED_AT);
    version2.setEncryptor(encryptor);
    version2.setUuid(UUID.randomUUID());
    version2.getCredential().setUuid(UUID.randomUUID());

    final Credential cred = new Credential("federation");
    cred.setUuid(UUID.fromString(UUID_STRING));

    credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialVersion.getCredential()).thenReturn(cred);
    when(credentialVersion.getName()).thenReturn(cred.getName());
    when(credentialVersion.getUuid()).thenReturn(cred.getUuid());
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);
  }

  @Test
  public void deleteCredential_whenTheDeletionSucceeds_deletesTheCredential() {
    when(credentialService.delete(eq(CREDENTIAL_NAME))).thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
      .thenReturn(true);

    subjectWithAcls.deleteCredential(CREDENTIAL_NAME);

    verify(credentialService, times(1)).delete(eq(CREDENTIAL_NAME));
  }

  @Test
  public void deleteCredential_whenTheCredentialIsNotDeleted_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
      .thenReturn(true);
    when(credentialService.delete(eq(CREDENTIAL_NAME))).thenReturn(false);

    try {
      subjectWithAcls.deleteCredential(CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void deleteCredential_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
      .thenReturn(false);
    when(credentialService.delete(CREDENTIAL_NAME))
      .thenReturn(true);

    try {
      subjectWithAcls.deleteCredential(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(credentialService, times(0)).delete(any());
  }

  @Test
  public void deleteCredential_whenAclsDisabled_doesNotCheckPermission_andDeletesTheCredential() {
    when(credentialService.delete(eq(CREDENTIAL_NAME))).thenReturn(true);

    subjectWithoutAcls.deleteCredential(CREDENTIAL_NAME);

    verify(credentialService, times(1)).delete(eq(CREDENTIAL_NAME));
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_returnsADataResponse() {
    final List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(credentialService.findAllByName(eq(CREDENTIAL_NAME)))
      .thenReturn(credentials);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    final DataResponse credentialVersions = subjectWithAcls.getAllCredentialVersions(CREDENTIAL_NAME);

    final List<CredentialView> credentialViews = credentialVersions.getData();
    assertThat(credentialViews, hasSize(2));
    assertThat(credentialViews.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    assertThat(credentialViews.get(1).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(1).getVersionCreatedAt(), equalTo(VERSION2_CREATED_AT));
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialDoesNotExist_throwsException() {
    when(credentialService.findAllByName(eq(CREDENTIAL_NAME)))
      .thenReturn(emptyList());
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    try {
      subjectWithAcls.getAllCredentialVersions(CREDENTIAL_NAME
      );
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void getAllCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.getAllCredentialVersions(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(credentialService, times(0)).findAllByName(any());
  }

  @Test
  public void getAllCredentialVersions_whenAclsDisabled_doesNotCheckPermission_andReturnsADataResponse() {
    final List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(credentialService.findAllByName(eq(CREDENTIAL_NAME)))
      .thenReturn(credentials);

    final DataResponse credentialVersions = subjectWithoutAcls.getAllCredentialVersions(CREDENTIAL_NAME);

    final List<CredentialView> credentialViews = credentialVersions.getData();
    assertThat(credentialViews, hasSize(2));
    assertThat(credentialViews.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    assertThat(credentialViews.get(1).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(1).getVersionCreatedAt(), equalTo(VERSION2_CREATED_AT));
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void getCurrentCredentialVersion_whenTheCredentialExists_returnsDataResponse() {
    when(credentialService.findActiveByName(eq(CREDENTIAL_NAME)))
      .thenReturn(Collections.singletonList(version1));
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    final DataResponse dataResponse = subjectWithAcls.getCurrentCredentialVersions(
      CREDENTIAL_NAME
    );
    final CredentialView credentialView = dataResponse.getData().get(0);
    assertThat(credentialView.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialView.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getCurrentCredentialVersion_whenTheCredentialDoesNotExist_throwsException() {
    try {
      subjectWithAcls.getCurrentCredentialVersions(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void getCurrentCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.getCurrentCredentialVersions(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(credentialService, times(0)).findActiveByName(any());

  }

  @Test
  public void getCurrentCredentialVersion_whenAclsDisabled_andWhenTheCredentialExists_doesNotCheckPermission_returnsDataResponse() {
    when(credentialService.findActiveByName(eq(CREDENTIAL_NAME)))
      .thenReturn(Collections.singletonList(version1));


    final DataResponse dataResponse = subjectWithoutAcls.getCurrentCredentialVersions(
      CREDENTIAL_NAME
    );
    final CredentialView credentialView = dataResponse.getData().get(0);
    assertThat(credentialView.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialView.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());

  }

  @Test
  public void getCredentialVersionByUUID_whenTheVersionExists_returnsDataResponse() {
    when(credentialService.findVersionByUuid(UUID_STRING))
      .thenReturn(version1);
    when(credentialService.findByUuid(UUID.fromString(UUID_STRING))).thenReturn(version1.getCredential());
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    final CredentialView credentialVersion = subjectWithAcls.getCredentialVersionByUUID(UUID_STRING);
    assertThat(credentialVersion.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersion.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getCredentialVersionByUUID_whenTheUserLacksPermission_throwsException() {
    PasswordCredentialVersion credential = new PasswordCredentialVersion(CREDENTIAL_NAME);
    when(credentialService.findVersionByUuid(UUID_STRING)).thenReturn(credential);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.getCredentialVersionByUUID(UUID_STRING);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    //invoked once in check permissions
    verify(credentialService, times(1)).findVersionByUuid(any());

  }

  @Test
  public void getCredentialVersionByUUID_whenAclsDisabled_andWhenTheVersionExists_doesNotCheckPermission_returnsDataResponse() {
    when(credentialService.findVersionByUuid(UUID_STRING))
      .thenReturn(version1);
    when(credentialService.findByUuid(UUID.fromString(UUID_STRING))).thenReturn(version1.getCredential());

    final CredentialView credentialVersion = subjectWithoutAcls.getCredentialVersionByUUID(UUID_STRING);
    assertThat(credentialVersion.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersion.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void getNCredentialVersions_whenTheCredentialExists_addsToAuditRecord() {
    final List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(credentialService.findNByName(CREDENTIAL_NAME, 2))
      .thenReturn(credentials);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    subjectWithAcls.getNCredentialVersions(CREDENTIAL_NAME, 2);

    assertEquals(2, auditRecord.getResourceList().size());
    assertEquals(2, auditRecord.getVersionList().size());
  }

  @Test
  public void getNCredentialVersions_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(false);

    try {
      subjectWithAcls.getNCredentialVersions(CREDENTIAL_NAME, null);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    verify(credentialService, times(0)).findAllByName(any());

  }

  @Test
  public void getNCredentialVersions_whenTheCredentialExists_returnsCredentials() {
    final List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(credentialService.findNByName(CREDENTIAL_NAME, 2))
      .thenReturn(credentials);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
      .thenReturn(true);

    DataResponse nCredentialVersions = subjectWithAcls.getNCredentialVersions(CREDENTIAL_NAME, 2);

    assertEquals(2, nCredentialVersions.getData().size());
  }

  @Test
  public void getNCredentialVersions_whenAclsDisabled_andWhenTheCredentialExists_doesNotCheckPermissions_andReturnsCredentials() {
    final List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(credentialService.findNByName(CREDENTIAL_NAME, 2))
      .thenReturn(credentials);

    DataResponse nCredentialVersions = subjectWithoutAcls.getNCredentialVersions(CREDENTIAL_NAME, 2);

    assertEquals(2, nCredentialVersions.getData().size());
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void setCredential_AddsTheCredentialNameToTheAuditRecord() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName(CREDENTIAL_NAME);

    when(permissionCheckingService.hasPermission(USER, setRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.setCredential(setRequest);

    verify(credentialService).save(null, password, setRequest);
    assertThat(auditRecord.getResourceName(), Matchers.equalTo("federation"));
    assertThat(auditRecord.getResourceUUID(), Matchers.equalTo(UUID_STRING));
    assertThat(auditRecord.getVersionUUID(), Matchers.equalTo(credentialVersion.getUuid().toString()));
  }

  @Test
  public void setCredential_whenPasswordSetRequest_passesCorrectParametersIncludingGeneration() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName(CREDENTIAL_NAME);

    when(permissionCheckingService.hasPermission(USER, setRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.setCredential(setRequest);

    verify(credentialService).save(null, password, setRequest);
  }

  @Test
  public void setCredential_whenNonPasswordSetRequest_passesCorrectParametersWithNullGeneration() {
    final UserSetRequest setRequest = new UserSetRequest();
    final UserCredentialValue userCredentialValue = new UserCredentialValue(
      "Picard",
      "Enterprise",
      "salt");

    setRequest.setType("user");
    setRequest.setName(CREDENTIAL_NAME);
    setRequest.setUserValue(userCredentialValue);

    when(permissionCheckingService.hasPermission(USER, setRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.setCredential(setRequest);

    verify(credentialService).save(null, userCredentialValue, setRequest);
  }

  @Test
  public void setCredential_withACertificateSetRequest_andNoCaName_usesCorrectParameters() {
    final CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue certificateValue = new CertificateCredentialValue(
      null,
      TestConstants.TEST_INTERMEDIATE_CA,
      TestConstants.TEST_INTERMEDIATE_CA_PRIVATE_KEY,
      null,
      false,
      false,
      false,
      false
    );

    setRequest.setType("certificate");
    setRequest.setName(CREDENTIAL_NAME);
    setRequest.setCertificateValue(certificateValue);

    when(permissionCheckingService.hasPermission(USER, setRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.setCredential(setRequest);

    final CertificateCredentialValue expected = new CertificateCredentialValue(
      null,
      TestConstants.TEST_INTERMEDIATE_CA,
      TestConstants.TEST_INTERMEDIATE_CA_PRIVATE_KEY,
      null,
      false,
      false,
      false,
      false
    );

    expected.setCertificateAuthority(true);
    expected.setSelfSigned(false);

    final ArgumentCaptor<CertificateSetRequest> setRequestArgumentCaptor = ArgumentCaptor.forClass(CertificateSetRequest.class);

    verify(credentialService).save(eq(null), eq(certificateValue), setRequestArgumentCaptor.capture());
    CertificateCredentialValue actualValue = setRequestArgumentCaptor.getValue().getCertificateValue();
    assertEquals(expected, actualValue);
  }

  @Test
  public void setCredential_withACertificateSetRequest_andACaName_providesCaCertificate() {
    final CertificateCredentialValue cerificateAuthority = new CertificateCredentialValue(
      null,
      TestConstants.TEST_CA,
      null,
      null,
      false,
      false,
      false,
      false
    );

    when(permissionCheckingService.hasPermission(USER, "/test-ca-name", PermissionOperation.READ))
      .thenReturn(true);

    when(certificateAuthorityService.findActiveVersion("/test-ca-name"))
      .thenReturn(cerificateAuthority);

    final CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue credentialValue = new CertificateCredentialValue(
      null,
      TestConstants.TEST_CERTIFICATE,
      "Enterprise",
      "test-ca-name",
      false,
      false,
      false,
      false
    );

    setRequest.setType("certificate");
    setRequest.setName("/captain");
    setRequest.setCertificateValue(credentialValue);

    final CertificateCredentialValue expectedCredentialValue = new CertificateCredentialValue(
      TestConstants.TEST_CA,
      TestConstants.TEST_CERTIFICATE,
      "Enterprise",
      "/test-ca-name",
      false,
      false,
      false,
      false
    );
    final ArgumentCaptor<CredentialValue> credentialValueArgumentCaptor = ArgumentCaptor.forClass(CredentialValue.class);

    when(permissionCheckingService.hasPermission(USER, setRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.setCredential(setRequest);

    verify(credentialService).save(eq(null), credentialValueArgumentCaptor.capture(), eq(setRequest));
    assertThat(credentialValueArgumentCaptor.getValue(), samePropertyValuesAs(expectedCredentialValue));
  }

  @Test
  public void setCredential_whenAclsDisabled_whenPasswordSetRequest_doesNotCheckPermissions_setsCredential() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName(CREDENTIAL_NAME);

    final CredentialVersion credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialVersion.getUuid()).thenReturn(UUID.fromString(UUID_STRING));

    when(credentialService.save(null, password, setRequest)).thenReturn(credentialVersion);

    final CredentialView credentialView = subjectWithoutAcls.setCredential(setRequest);

    assertEquals(UUID_STRING, credentialView.getUuid());

    verify(credentialService).save(null, password, setRequest);
    verify(permissionCheckingService, times(0)).hasPermission(any(), anyString(), any());
  }

  @Test
  public void setCredential_whenPasswordSetRequest_setsCredential() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName(CREDENTIAL_NAME);

    final CredentialVersion credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialVersion.getName()).thenReturn(CREDENTIAL_NAME);
    when(credentialVersion.getUuid()).thenReturn(UUID.fromString(UUID_STRING));

    when(credentialService.save(null, password, setRequest)).thenReturn(credentialVersion);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(true);

    final CredentialView credentialView = subjectWithAcls.setCredential(setRequest);

    assertEquals(UUID_STRING, credentialView.getUuid());

    verify(credentialService).save(null, password, setRequest);
    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
  }

  @Test
  public void setCredential_whenUserLacksPermission_throwsException() {
    final StringCredentialValue password = new StringCredentialValue("federation");
    final PasswordSetRequest setRequest = new PasswordSetRequest();

    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName(CREDENTIAL_NAME);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAcls.setCredential(setRequest);
      fail("should throw exception");
    } catch (final PermissionException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
    //invoked once in check permissions
    verify(permissionCheckingService, times(1)).hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE);
    verify(credentialService, times(0)).save(any(), any(), any());

  }

  @Test
  public void generateCredential_whenPasswordGenerateRequest_passesCorrectParametersIncludingGeneration() {
    final PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("/captain");
    generateRequest.setOverwrite(false);

    when(permissionCheckingService.hasPermission(USER, generateRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.generateCredential(generateRequest);

    verify(credentialService).save(null, null, generateRequest);
  }

  @Test
  public void generateCredential_addsToCEFAuditRecord() {
    final PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();
    final UUID uuid = UUID.randomUUID();

    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("/captain");
    generateRequest.setOverwrite(false);

    Credential credential = new Credential("/captain");
    final PasswordCredentialVersionData delegate = mock(PasswordCredentialVersionData.class);
    credential.setUuid(uuid);
    credential.setName("/captain");
    when(delegate.getCredential()).thenReturn(credential);
    when(delegate.getUuid()).thenReturn(uuid);

    final CredentialVersion credentialVersion = new PasswordCredentialVersion(delegate);
    credentialVersion.setEncryptor(encryptor);
    credentialVersion.setValue("some-value");
    credentialVersion.setCredential(credential);
    credentialVersion.setUuid(uuid);

    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);

    when(permissionCheckingService.hasPermission(USER, generateRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    subjectWithAcls.generateCredential(generateRequest);

    assertEquals("/captain", auditRecord.getResourceName());
    assertEquals(uuid.toString(), auditRecord.getVersionUUID());
  }

  @Test
  public void generateCredential_whenCADoesNotExist_throwsException() {
    String caName = "caName";
    CertificateGenerationRequestParameters requestParameters = new CertificateGenerationRequestParameters();
    requestParameters.setCaName(caName);

    CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setRequestGenerationParameters(requestParameters);
    generateRequest.setName("generateRequestName");
    generateRequest.setType(CredentialType.CERTIFICATE.toString());

    when(certificateAuthorityService.findActiveVersion(caName))
      .thenThrow(new EntryNotFoundException(ErrorMessages.Credential.CERTIFICATE_ACCESS));

    when(permissionCheckingService.hasPermission(USER, generateRequest.getName(), PermissionOperation.WRITE))
      .thenReturn(true);

    try {
      subjectWithAcls.generateCredential(generateRequest);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.CERTIFICATE_ACCESS));
    }

    verify(credentialService, times(0)).findMostRecent(any());
    verify(universalCredentialGenerator, times(0)).generate(any());
    verify(credentialService, times(0)).save(any(), any(), any());
  }

  @Test
  public void generateCredential_whenUserLacksPermission_throwsException() {
    final PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();
    generateRequest.setName(CREDENTIAL_NAME);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.WRITE))
      .thenReturn(false);

    try {
      subjectWithAcls.generateCredential(generateRequest);
      fail("should throw exception");
    } catch (final PermissionException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }

    verify(credentialService, times(0)).findMostRecent(any());
    verify(universalCredentialGenerator, times(0)).generate(any());
    verify(credentialService, times(0)).save(any(), any(), any());
  }

  @Test
  public void findStartingWithPath_withAclsEnabled_andUserLacksPermissions_returnsEmptyList() {
    when(permissionCheckingService.findAllPathsByActor(USER)).thenReturn(EMPTY_SET);

    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findStartingWithPath("/", ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithAcls.findStartingWithPath("/", "");

    assertEquals(0, results.size());
  }

  @Test
  public void findStartingWithPath_withAclsEnabled_andUserHasPermissions_returnsCredentials() {
    HashSet<String> paths = new HashSet<>(Collections.singletonList(CREDENTIAL_NAME));
    when(permissionCheckingService.findAllPathsByActor(USER)).thenReturn(paths);

    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findStartingWithPath("/", ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithAcls.findStartingWithPath("/", "");

    assertEquals(1, results.size());
    assertTrue(results.contains(credential));
  }

  @Test
  public void findStartingWithPath_withAclsDisabled_returnsUnfilteredCredentials() {
    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findStartingWithPath("/", ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithoutAcls.findStartingWithPath("/", "");

    assertEquals(1, results.size());
    assertTrue(results.contains(credential));
    verify(permissionCheckingService, times(0)).findAllPathsByActor(any());
  }

  @Test
  public void findContainingName_withAclsEnabled_andUserLacksPermissions_returnsEmptyList() {
    when(permissionCheckingService.findAllPathsByActor(USER)).thenReturn(EMPTY_SET);

    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findContainingName(CREDENTIAL_NAME, ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithAcls.findContainingName(CREDENTIAL_NAME, "");

    assertEquals(0, results.size());
  }

  @Test
  public void findContainingName_withAclsEnabled_andUserHasPermissions_returnsCredentials() {
    HashSet<String> paths = new HashSet<>(Collections.singletonList(CREDENTIAL_NAME));
    when(permissionCheckingService.findAllPathsByActor(USER)).thenReturn(paths);

    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findContainingName(CREDENTIAL_NAME, ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithAcls.findContainingName(CREDENTIAL_NAME, "");

    assertEquals(1, results.size());
    assertTrue(results.contains(credential));
  }

  @Test
  public void findContainingName_withAclsDisabled_returnsUnfilteredCredentials() {
    FindCredentialResult credential = new FindCredentialResult(Instant.now(), CREDENTIAL_NAME);
    when(credentialService.findContainingName(CREDENTIAL_NAME, ""))
      .thenReturn(Collections.singletonList(credential));

    List<FindCredentialResult> results = subjectWithoutAcls.findContainingName(CREDENTIAL_NAME, "");

    assertEquals(1, results.size());
    assertTrue(results.contains(credential));
    verify(permissionCheckingService, times(0)).findAllPathsByActor(any());
  }

}
