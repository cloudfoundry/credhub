package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidPermissionOperationException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.view.FindCredentialResult;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class PermissionedCredentialServiceTest {

  private static final String UUID_STRING = "expected UUID";
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

  private PermissionedCredentialService subject;
  private CredentialVersion existingCredentialVersion;
  private UserContext userContext;
  private List<EventAuditRecordParameters> auditRecordParameters;
  private StringGenerationParameters generationParameters;
  private CredentialValue credentialValue;
  private List<PermissionEntry> accessControlEntries;


  @Before
  public void setUp() throws Exception {
    initMocks(this);

    userContext = mock(UserContext.class);
    UserContextHolder userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);

    subject = new PermissionedCredentialService(
        credentialVersionDataService,
        credentialFactory,
        permissionCheckingService,
        certificateAuthorityService,
        userContextHolder);

    auditRecordParameters = new ArrayList<>();
    generationParameters = mock(StringGenerationParameters.class);
    credentialValue = mock(CredentialValue.class);
    accessControlEntries = new ArrayList<>();

    when(userContext.getActor()).thenReturn(USER);

    existingCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
    existingCredentialVersion.setEncryptor(encryptor);

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, WRITE))
        .thenReturn(true);
    when(credentialVersionDataService.findByUuid(UUID_STRING))
        .thenReturn(existingCredentialVersion);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void save_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "user",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "no-overwrite",
        auditRecordParameters
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteIsFalse_logsCREDENTIAL_ACCESS() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "no-overwrite",
        auditRecordParameters
    );

    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteIsTrue_logsCREDENTIAL_UPDATE() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));

    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "overwrite",
        auditRecordParameters
    );

    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_UPDATE));
    assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void save_whenThereIsANewCredentialAndSelfUpdatingAcls_throwsException() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(null);
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    when(permissionCheckingService
        .userAllowedToOperateOnActor("test-user"))
        .thenReturn(true);
    when(permissionCheckingService
        .hasPermission(userContext.getActor(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(true);

    accessControlEntries.add(new PermissionEntry("test-user", Arrays.asList(WRITE, WRITE_ACL)));
    try {
      subject.save(
          existingCredentialVersion, CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          "overwrite",
          auditRecordParameters
      );
    } catch (InvalidPermissionOperationException e) {
      assertThat(e.getMessage(), equalTo("error.permission.invalid_update_operation"));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredential_shouldCallVerifyCredentialWritePermission() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "no-overwrite",
        auditRecordParameters
    );

    verify(permissionCheckingService).hasPermission(userContext.getActor(),
        CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldNotCallVerifyCredentialWritePermission() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "no-overwrite",
        auditRecordParameters
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialWithACEs_shouldThrowAnExceptionIfItLacksPermission() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(permissionCheckingService
        .hasPermission(userContext.getActor(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);

    accessControlEntries
        .add(new PermissionEntry("some_actor", Arrays.asList(PermissionOperation.READ_ACL)));

    try {
      subject.save(
          existingCredentialVersion, CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          "no-overwrite",
          auditRecordParameters
      );
    } catch (PermissionException pe) {
      assertThat(pe.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverWriteIsTrue_shouldNotAddAceForTheCurrentUser() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    subject.save(
        existingCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "overwrite",
        auditRecordParameters
    );

    assertThat(accessControlEntries, hasSize(0));
  }

  @Test
  public void save_whenWritingCredential_savesANewVersion() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    when(credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf("password"),
        CREDENTIAL_NAME,
        credentialValue,
        null,
        generationParameters)).thenReturn(newVersion);

    subject.save(
        null, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "overwrite",
        auditRecordParameters
    );

    verify(credentialVersionDataService).save(newVersion);
  }


  @Test
  public void delete_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
        .thenReturn(false);

    try {
      subject.delete(CREDENTIAL_NAME, auditRecordParameters);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      assertThat(auditRecordParameters, hasSize(1));
      assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
          equalTo(CREDENTIAL_DELETE));
    }
  }

  @Test
  public void findAllByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findAllByName(CREDENTIAL_NAME, auditRecordParameters);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      assertThat(auditRecordParameters, hasSize(1));
      assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
          equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void findNByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findNByName(CREDENTIAL_NAME, 1, auditRecordParameters);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      assertThat(auditRecordParameters, hasSize(1));
      assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
          equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void getNCredentialVersions_whenTheNumberOfCredentialsIsNegative_throws() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    try {
      subject.findNByName(CREDENTIAL_NAME, -1, auditRecordParameters);
      fail("should throw exception");
    } catch (InvalidQueryParameterException e) {
      assertThat(e.getInvalidQueryParameter(), equalTo("versions"));
      assertThat(e.getMessage(), equalTo("error.invalid_query_parameter"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_setsCorrectAuditingParametersAndReturnsTheCredential() {
    final CredentialVersion credentialVersionFound = subject.findByUuid(UUID_STRING, auditRecordParameters);

    assertThat(credentialVersionFound, equalTo(existingCredentialVersion));

    assertThat(auditRecordParameters, hasSize(1));
    assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
        equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
    when(credentialVersionDataService.findByUuid(UUID_STRING))
        .thenReturn(null);

    try {
      subject.findByUuid(UUID_STRING, auditRecordParameters);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheUserLacksPermission_throwsExceptionAndSetsCorrectAuditingParameters() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findByUuid(UUID_STRING, auditRecordParameters);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      assertThat(auditRecordParameters, hasSize(1));
      assertThat(auditRecordParameters.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
          equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void findAllCertificateCredentialsByCaName_whenTheUserHasPermission_getsAllCertificateCredentialsByCaName() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    ArrayList<String> expectedCertificates = newArrayList("expectedCertificate");
    when(credentialVersionDataService.findAllCertificateCredentialsByCaName(CREDENTIAL_NAME))
        .thenReturn(expectedCertificates);

    List<String> foundCertificates = subject
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
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void findStartingWithPath_updatesAuditLoginWithFindRequest() {
    when(credentialVersionDataService.findStartingWithPath("test_path")).thenReturn(new ArrayList<FindCredentialResult>());
    subject.findStartingWithPath("test_path", auditRecordParameters);
    assertThat(auditRecordParameters, hasSize(1));
    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
        equalTo(CREDENTIAL_FIND));
  }

  @Test
  public void findContainingName_updatesAuditLoginWithFindRequest() {
    when(credentialVersionDataService.findContainingName("test_path")).thenReturn(new ArrayList<FindCredentialResult>());
    subject.findContainingName("test_path", auditRecordParameters);
    assertThat(auditRecordParameters, hasSize(1));
    assertThat(auditRecordParameters.get(0).getAuditingOperationCode(),
        equalTo(CREDENTIAL_FIND));
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteModeIsConvergeAndParametersAreSame_DoesNotOverwriteCredential() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    CredentialVersion originalCredentialVersion = mock(CredentialVersion.class);
    when(originalCredentialVersion.matchesGenerationParameters(generationParameters)).thenReturn(true);

    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion);
    when(originalCredentialVersion.getCredentialType()).thenReturn("password");

    when(credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf("password"),
        CREDENTIAL_NAME,
        credentialValue,
        originalCredentialVersion,
        generationParameters)).thenReturn(newVersion);

    subject.save(
        originalCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "converge",
        auditRecordParameters
    );

    verify(credentialVersionDataService, never()).save(newVersion);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteModeIsConvergeAndParametersAreDifferent_OverwritesCredential() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    final PasswordCredentialVersion newVersion = new PasswordCredentialVersion();

    CredentialVersion originalCredentialVersion = mock(CredentialVersion.class);
    when(originalCredentialVersion.matchesGenerationParameters(generationParameters)).thenReturn(false);

    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(originalCredentialVersion);
    when(originalCredentialVersion.getCredentialType()).thenReturn("password");

    when(credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf("password"),
        CREDENTIAL_NAME,
        credentialValue,
        originalCredentialVersion,
        generationParameters)).thenReturn(newVersion);

    subject.save(
        originalCredentialVersion, CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        "converge",
        auditRecordParameters
    );

    verify(credentialVersionDataService).save(newVersion);
  }
}
