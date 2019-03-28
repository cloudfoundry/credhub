package org.cloudfoundry.credhub.services;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.data.CredentialDataService;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.PermissionException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.BaseCredentialRequest;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.cloudfoundry.credhub.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.PermissionOperation.READ;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.PermissionOperation.WRITE_ACL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class DefaultPermissionedCredentialServiceTest {

  private static final String VERSION_UUID_STRING = "expected UUID";
  private static final UUID CREDENTIAL_UUID = UUID.randomUUID();
  private static final String CREDENTIAL_NAME = "/Picard";
  private static final String USER = "Kirk";

  @Mock
  private CredentialVersionDataService credentialVersionDataService;

  @Mock
  private PermissionCheckingService permissionCheckingService;

  @Mock
  private Encryptor encryptor;

  @Mock
  private CredentialFactory credentialFactory;

  @Mock
  private CertificateAuthorityService certificateAuthorityService;

  @Mock
  private CredentialDataService credentialDataService;

  @Mock
  private CEFAuditRecord auditRecord;

  private PermissionedCredentialService subject;
  private CredentialVersion existingCredentialVersion;
  private UserContext userContext;
  private StringGenerationParameters generationParameters;
  private CredentialValue credentialValue;
  private List<PermissionEntry> accessControlEntries;
  private final BaseCredentialRequest request = mock(BaseCredentialRequest.class);
  private Credential credential;

  @Before
  public void setUp() {
    initMocks(this);

    userContext = mock(UserContext.class);
    final UserContextHolder userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);

    subject = new DefaultPermissionedCredentialService(
      credentialVersionDataService,
      credentialFactory,
      permissionCheckingService,
      certificateAuthorityService,
      userContextHolder, credentialDataService, auditRecord
    );

    generationParameters = mock(StringGenerationParameters.class);
    credentialValue = mock(CredentialValue.class);
    credential = new Credential(CREDENTIAL_NAME);
    accessControlEntries = new ArrayList<>();

    when(userContext.getActor()).thenReturn(USER);

    existingCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
    existingCredentialVersion.setEncryptor(encryptor);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, WRITE))
      .thenReturn(true);
    when(credentialDataService.findByUUID(CREDENTIAL_UUID))
      .thenReturn(credential);
    when(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
      .thenReturn(existingCredentialVersion);

    when(request.getName()).thenReturn(CREDENTIAL_NAME);
    when(request.getGenerationParameters()).thenReturn(generationParameters);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
    when(request.getType()).thenReturn("user");
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    subject.save(existingCredentialVersion, credentialValue, request);
  }

  @Test
  public void save_whenThereIsANewCredentialAndSelfUpdatingAcls_throwsException() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(null);
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    when(permissionCheckingService
      .userAllowedToOperateOnActor("test-user"))
      .thenReturn(true);
    when(permissionCheckingService
      .hasPermission(userContext.getActor(), CREDENTIAL_NAME, WRITE_ACL))
      .thenReturn(true);

    accessControlEntries.add(new PermissionEntry("test-user", "test-path", Arrays.asList(WRITE, WRITE_ACL)));
    try {
      subject.save(existingCredentialVersion, credentialValue, request);
    } catch (final InvalidPermissionOperationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredential_shouldCallVerifyCredentialWritePermission() {
    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(existingCredentialVersion, credentialValue, request);

    verify(permissionCheckingService).hasPermission(userContext.getActor(),
      CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldNotCallVerifyCredentialWritePermission() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    subject.save(existingCredentialVersion, credentialValue, request);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialWithACEs_shouldThrowAnExceptionIfItLacksPermission() {
    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(permissionCheckingService
      .hasPermission(userContext.getActor(), CREDENTIAL_NAME, WRITE_ACL))
      .thenReturn(false);

    accessControlEntries
      .add(new PermissionEntry("some_actor", "test-path", Arrays.asList(PermissionOperation.READ_ACL)));

    try {
      subject.save(existingCredentialVersion, credentialValue, request);
    } catch (final PermissionException pe) {
      assertThat(pe.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverWriteIsTrue_shouldNotAddACEForTheCurrentUser() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    subject.save(existingCredentialVersion, credentialValue, request);

    assertThat(accessControlEntries, hasSize(0));
  }

  @Test
  public void save_whenWritingCredential_savesANewVersion() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    when(credentialFactory.makeNewCredentialVersion(
      CredentialType.valueOf("PASSWORD"),
      CREDENTIAL_NAME,
      credentialValue,
      null,
      generationParameters)).thenReturn(newVersion);

    subject.save(null, credentialValue, request);

    verify(credentialVersionDataService).save(newVersion);
  }


  @Test
  public void delete_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
      .thenReturn(false);

    try {
      subject.delete(CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void findAllByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(false);

    try {
      subject.findAllByName(CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void findAllByName_addsToTheAuditRecord() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);

    final List<CredentialVersion> expectedCredentials = newArrayList(existingCredentialVersion);
    when(credentialVersionDataService.findAllByName(CREDENTIAL_NAME))
      .thenReturn(expectedCredentials);

    subject.findAllByName(CREDENTIAL_NAME);

    verify(auditRecord, times(1)).addResource(any(Credential.class));
    verify(auditRecord, times(1)).addVersion(any(CredentialVersion.class));

  }

  @Test
  public void findActiveByName_addsToTheAuditRecord() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);

    final List<CredentialVersion> expectedCredentials = newArrayList(existingCredentialVersion);
    when(credentialVersionDataService.findActiveByName(CREDENTIAL_NAME))
      .thenReturn(expectedCredentials);

    subject.findActiveByName(CREDENTIAL_NAME);

    verify(auditRecord, times(1)).addResource(any(Credential.class));
    verify(auditRecord, times(1)).addVersion(any(CredentialVersion.class));

  }

  @Test
  public void findVersionByUuid_addsToTheAuditRecord() {
    when(credentialVersionDataService.findByUuid(CREDENTIAL_UUID.toString()))
      .thenReturn(existingCredentialVersion);

    subject.findVersionByUuid(CREDENTIAL_UUID.toString());

    verify(auditRecord, times(1)).setResource(any(Credential.class));
    verify(auditRecord, times(1)).setVersion(any(CredentialVersion.class));

  }

  @Test
  public void findNByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(false);

    try {
      subject.findNByName(CREDENTIAL_NAME, 1);
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void getNCredentialVersions_whenTheNumberOfCredentialsIsNegative_throws() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);

    try {
      subject.findNByName(CREDENTIAL_NAME, -1);
      fail("should throw exception");
    } catch (final InvalidQueryParameterException e) {
      assertThat(e.getInvalidQueryParameter(), equalTo("versions"));
      assertThat(e.getMessage(), equalTo(ErrorMessages.INVALID_QUERY_PARAMETER));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_returnsTheCredential() {
    final CredentialVersion credentialVersionFound = subject
      .findVersionByUuid(VERSION_UUID_STRING);

    assertThat(credentialVersionFound, equalTo(existingCredentialVersion));
  }

  @Test
  public void getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
    when(credentialVersionDataService.findByUuid(VERSION_UUID_STRING))
      .thenReturn(null);

    try {
      subject.findVersionByUuid(VERSION_UUID_STRING);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void getCredentialVersion_whenTheUserLacksPermission_throwsExceptionAndSetsCorrectAuditingParameters() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(false);

    try {
      subject.findVersionByUuid(VERSION_UUID_STRING);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void findAllCertificateCredentialsByCaName_whenTheUserHasPermission_getsAllCertificateCredentialsByCaName() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);

    final List<String> expectedCertificates = newArrayList("expectedCertificate");
    when(credentialVersionDataService.findAllCertificateCredentialsByCaName(CREDENTIAL_NAME))
      .thenReturn(expectedCertificates);

    final List<String> foundCertificates = subject
      .findAllCertificateCredentialsByCaName(CREDENTIAL_NAME);

    assertThat(foundCertificates, equalTo(expectedCertificates));
  }

  @Test
  public void findAllCertificateCredentialsByCaName_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(false);

    try {
      subject.findAllCertificateCredentialsByCaName(CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndParametersAreSame_DoesNotOverwriteCredential() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    final BaseCredentialGenerateRequest generateRequest = mock(BaseCredentialGenerateRequest.class);
    when(generateRequest.getName()).thenReturn(CREDENTIAL_NAME);
    when(generateRequest.getGenerationParameters()).thenReturn(generationParameters);

    when(generateRequest.getType()).thenReturn("password");
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    final CredentialVersion originalCredentialVersion = mock(CredentialVersion.class);
    when(originalCredentialVersion.matchesGenerationParameters(generationParameters)).thenReturn(true);

    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion);
    when(originalCredentialVersion.getCredentialType()).thenReturn("password");

    when(credentialFactory.makeNewCredentialVersion(
      CredentialType.valueOf("PASSWORD"),
      CREDENTIAL_NAME,
      credentialValue,
      originalCredentialVersion,
      generationParameters)).thenReturn(newVersion);

    subject.save(originalCredentialVersion, credentialValue, generateRequest);

    verify(credentialVersionDataService, never()).save(newVersion);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndParametersAreDifferent_OverwritesCredential() {
    final PasswordCredentialVersion stubPasswordCredentialVersion = new PasswordCredentialVersion();
    stubPasswordCredentialVersion.setEncryptor(encryptor);

    when(request.getType()).thenReturn("password");
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
      .thenReturn(stubPasswordCredentialVersion);
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    final CredentialVersion originalCredentialVersion = mock(CredentialVersion.class);
    when(originalCredentialVersion.matchesGenerationParameters(generationParameters)).thenReturn(false);

    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion);
    when(originalCredentialVersion.getCredentialType()).thenReturn("password");

    when(credentialFactory.makeNewCredentialVersion(
      CredentialType.valueOf("PASSWORD"),
      CREDENTIAL_NAME,
      credentialValue,
      originalCredentialVersion,
      generationParameters)).thenReturn(newVersion);

    subject.save(originalCredentialVersion, credentialValue, request);

    verify(credentialVersionDataService).save(newVersion);
  }

  @Test
  public void findByUuid_whenTheUUIDCorrespondsToACredential_andTheUserHasPermission_returnsTheCredential() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(true);

    assertThat(subject.findByUuid(CREDENTIAL_UUID), equalTo(credential));
  }

  @Test
  public void findByUuid_whenTheUUIDCorrespondsToACredential_andTheUserDoesNotHavePermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
      .thenReturn(false);

    try {
      subject.findByUuid(CREDENTIAL_UUID);
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

  @Test
  public void findByUuid_whenNoMatchingCredentialExists_throwsEntryNotFound() {
    try {
      subject.findByUuid(UUID.randomUUID());
      fail("Should throw exception");
    } catch (final EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_ACCESS));
    }
  }

}
