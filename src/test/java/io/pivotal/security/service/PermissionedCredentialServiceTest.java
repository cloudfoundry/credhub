package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
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
  private PermissionsDataService permissionsDataService;

  @Mock
  private PermissionService permissionService;

  @Mock
  private PermissionCheckingService permissionCheckingService;

  @Mock
  private Encryptor encryptor;

  @Mock
  private CredentialFactory credentialFactory;

  private PermissionedCredentialService subject;

  private CredentialVersion existingCredentialVersion;
  private UserContext userContext;
  private List<EventAuditRecordParameters> auditRecordParameters;
  private StringGenerationParameters generationParameters;
  private CredentialValue credentialValue;
  private List<PermissionEntry> accessControlEntries;
  private PermissionEntry currentUserPermissions;
  private List<EventAuditRecordParameters> auditRecordParametersList;


  @Before
  public void setUp() throws Exception {
    initMocks(this);

    subject = new PermissionedCredentialService(
        credentialVersionDataService,
        permissionService,
        credentialFactory,
        permissionCheckingService);

    userContext = mock(UserContext.class);
    auditRecordParameters = new ArrayList<>();
    generationParameters = mock(StringGenerationParameters.class);
    credentialValue = mock(CredentialValue.class);
    accessControlEntries = new ArrayList<>();

    when(userContext.getAclUser()).thenReturn(USER);
    currentUserPermissions = new PermissionEntry(userContext.getAclUser(),
        Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));

    existingCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
    existingCredentialVersion.setEncryptor(encryptor);

    auditRecordParametersList = newArrayList();

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
        CREDENTIAL_NAME,
        "user",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverwriteIsFalse_logsCREDENTIAL_ACCESS() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
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
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
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
        .userAllowedToOperateOnActor(userContext, "test-user"))
        .thenReturn(false);

    accessControlEntries.add(new PermissionEntry("test-user", Arrays.asList(WRITE, WRITE_ACL)));
    try {

      subject.save(
          CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          true,
          userContext,
          currentUserPermissions,
          auditRecordParameters
      );
    } catch (InvalidAclOperationException e) {
      assertThat(e.getMessage(), equalTo("error.acl.invalid_update_operation"));
    }
  }

  @Test
  public void save_whenThereIsAnExistingCredential_shouldCallVerifyCredentialWritePermission() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionCheckingService).hasPermission(userContext.getAclUser(),
        CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldNotCallVerifyCredentialWritePermission() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionCheckingService, times(0)).hasPermission(
        userContext.getAclUser(), CREDENTIAL_NAME, WRITE);
  }

  @Test
  public void save_whenThereIsAnExistingCredentialWithACEs_shouldThrowAnExceptionIfItLacksPermission() {
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);
    when(permissionCheckingService
        .hasPermission(userContext.getAclUser(), CREDENTIAL_NAME, WRITE_ACL))
        .thenReturn(false);

    accessControlEntries
        .add(new PermissionEntry("some_actor", Arrays.asList(PermissionOperation.READ_ACL)));

    try {
      subject.save(
          CREDENTIAL_NAME,
          "password",
          credentialValue,
          generationParameters,
          accessControlEntries,
          false,
          userContext,
          currentUserPermissions,
          auditRecordParameters
      );
    } catch (PermissionException pe) {
      assertThat(pe.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void save_whenThereIsNoExistingCredential_shouldAddAceForTheCurrentUser() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(accessControlEntries, hasItem(
        samePropertyValuesAs(
            new PermissionEntry("Kirk", Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL))
        )
        )
    );
  }

  @Test
  public void save_whenThereIsAnExistingCredentialAndOverWriteIsTrue_shouldNotAddAceForTheCurrentUser() {
    when(credentialVersionDataService.save(any(CredentialVersion.class)))
        .thenReturn(new PasswordCredentialVersion().setEncryptor(encryptor));
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredentialVersion);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
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
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(credentialVersionDataService).save(newVersion);
  }

  @Test
  public void save_whenOverwriteIsTrue_shouldSaveAccessControlEntries() {
    PasswordCredentialVersion credential = new PasswordCredentialVersion().setEncryptor(encryptor);
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenReturn(credential);

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    verify(permissionService).saveAccessControlEntries(userContext, credential.getCredential(), accessControlEntries);
  }

  @Test
  public void save_whenOverwriteIsTrue_logsACL_UPDATE() {
    PasswordCredentialVersion credential = new PasswordCredentialVersion(CREDENTIAL_NAME).setEncryptor(encryptor);
    when(credentialVersionDataService.save(any(CredentialVersion.class))).thenReturn(credential);
    when(permissionCheckingService
        .userAllowedToOperateOnActor(userContext, "Spock")).thenReturn(true);
    when(permissionCheckingService
        .userAllowedToOperateOnActor(userContext, "McCoy")).thenReturn(true);

    accessControlEntries.addAll(Arrays.asList(
        new PermissionEntry("Spock", Arrays.asList(WRITE)),
        new PermissionEntry("McCoy", Arrays.asList(DELETE))
    ));

    subject.save(
        CREDENTIAL_NAME,
        "password",
        credentialValue,
        generationParameters,
        accessControlEntries,
        true,
        userContext,
        currentUserPermissions,
        auditRecordParameters
    );

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Spock")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "McCoy")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE_ACL, "Kirk")
        )));

    assertThat(auditRecordParameters, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ_ACL, "Kirk")
        )));
  }

  @Test
  public void delete_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
        .thenReturn(false);

    try {
      subject.delete(userContext, CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void findAllByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findAllByName(userContext, CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void findNByName_whenTheUserLacksPermission_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findNByName(userContext, CREDENTIAL_NAME, 1);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_setsCorrectAuditingParametersAndReturnsTheCredential() {
    final CredentialVersion credentialVersionFound = subject.findByUuid(userContext, UUID_STRING, auditRecordParametersList);

    assertThat(credentialVersionFound, equalTo(existingCredentialVersion));

    assertThat(auditRecordParametersList, hasSize(1));
    assertThat(auditRecordParametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(),
        equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
    when(credentialVersionDataService.findByUuid(UUID_STRING))
        .thenReturn(null);

    try {
      subject.findByUuid(userContext, UUID_STRING, auditRecordParametersList);
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
      subject.findByUuid(userContext, UUID_STRING, auditRecordParametersList);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
      assertThat(auditRecordParametersList, hasSize(1));
      assertThat(auditRecordParametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(),
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
        .findAllCertificateCredentialsByCaName(userContext, CREDENTIAL_NAME);

    assertThat(foundCertificates, equalTo(expectedCertificates));
  }

  @Test
  public void findAllCertificateCredentialsByCaName_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.findAllCertificateCredentialsByCaName(userContext, CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

}
