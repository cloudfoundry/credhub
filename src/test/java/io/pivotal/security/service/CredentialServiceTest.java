package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.constants.CredentialType;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;
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
public class CredentialServiceTest {

  @Mock
  private CredentialDataService credentialDataService;

  @Mock
  private AccessControlDataService accessControlDataService;

  @Mock
  private PermissionService permissionService;

  @Mock
  private Encryptor encryptor;

  @Mock
  private CredentialFactory credentialFactory;

  private CredentialService subject;

  private Credential existingCredential;
  private UserContext userContext;
  private List<EventAuditRecordParameters> parametersList;
  private StringGenerationParameters generationParameters;
  private CredentialValue credentialValue;
  private List<PermissionEntry> accessControlEntries;
  private PermissionEntry currentUserPermissions;

  private static final String CREDENTIAL_NAME = "/Picard";

  @Before
  public void setUp() throws Exception {
    initMocks(this);

    subject = new CredentialService(
        credentialDataService,
        accessControlDataService,
        permissionService,
        credentialFactory);

    userContext = mock(UserContext.class);
    parametersList = new ArrayList<>();
    generationParameters = mock(StringGenerationParameters.class);
    credentialValue = mock(CredentialValue.class);
    accessControlEntries = new ArrayList<>();

    when(userContext.getAclUser()).thenReturn("Kirk");
    currentUserPermissions = new PermissionEntry(userContext.getAclUser(),
        Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));

    existingCredential = new PasswordCredential();
    existingCredential.setEncryptor(encryptor);
  }

  @Test(expected = ParameterizedValidationException.class)
  public void performSet_whenGivenTypeAndExistingTypeDontMatch_throwsException() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        false,
        "user",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);
  }

  @Test
  public void performSet_whenThereIsAnExistingCredentialAndOverwriteIsFalse_itLogsCREDENTIAL_ACCESS() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        false,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    assertThat(parametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    assertThat(parametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void performSet_whenThereIsAnExistingCredentialAndOverwriteIsTrue_itLogsCREDENTIAL_UPDATE() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));

    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        true,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    assertThat(parametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_UPDATE));
    assertThat(parametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
  }

  @Test
  public void performSet_whenThereIsAnExistingCredential_itShouldCallVerifyCredentialWritePermission() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);
    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        false,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    verify(permissionService)
        .verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void performSet_whenThereIsNoExistingCredential_itShouldNotCallVerifyCredentialWritePermission() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        false,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    verify(permissionService, times(0))
        .verifyCredentialWritePermission(userContext, CREDENTIAL_NAME);
  }

  @Test
  public void performSet_whenThereIsNoExistingCredential_itShouldAddAceForTheCurrentUser() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        false,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    assertThat(accessControlEntries, hasItem(
        samePropertyValuesAs(
            new PermissionEntry("Kirk", Arrays.asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL))
        )
        )
    );
  }

  @Test
  public void performSet_whenThereIsAnExistingCredentialAndOverWriteIsTrue_itShouldNotAddAceForTheCurrentUser() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(existingCredential);

    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        true,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    assertThat(accessControlEntries, hasSize(0));
  }

  @Test
  public void performSet_whenWritingCredential_itSavesANewVersion() {
    when(credentialDataService.save(any(Credential.class)))
        .thenReturn(new PasswordCredential().setEncryptor(encryptor));
    final PasswordCredential newVersion = new PasswordCredential();

    when(credentialFactory.makeNewCredentialVersion(
        CredentialType.valueOf("password"),
        CREDENTIAL_NAME,
        credentialValue,
        null,
        generationParameters)).thenReturn(newVersion);

    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        true,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    verify(credentialDataService).save(newVersion);
  }

  @Test
  public void performSet_whenOverwriteIsTrue_itShouldSaveAccessControlEntries() {
    PasswordCredential credential = new PasswordCredential().setEncryptor(encryptor);
    when(credentialDataService.save(any(Credential.class))).thenReturn(credential);

    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        true,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    verify(accessControlDataService)
        .saveAccessControlEntries(credential.getCredentialName(), accessControlEntries);
  }

  @Test
  public void performSet_whenOverwriteIsTrue_itLogsACL_UPDATE() {
    PasswordCredential credential = new PasswordCredential(CREDENTIAL_NAME).setEncryptor(encryptor);
    when(credentialDataService.save(any(Credential.class))).thenReturn(credential);

    accessControlEntries.addAll(Arrays.asList(
        new PermissionEntry("Spock", Arrays.asList(WRITE)),
        new PermissionEntry("McCoy", Arrays.asList(DELETE))
    ));

    subject.save(
        userContext,
        parametersList,
        CREDENTIAL_NAME,
        true,
        "password",
        generationParameters,
        credentialValue,
        accessControlEntries,
        currentUserPermissions);

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Spock")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "McCoy")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, DELETE, "Kirk")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ, "Kirk")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE, "Kirk")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, WRITE_ACL, "Kirk")
        )));

    assertThat(parametersList, hasItem(
        samePropertyValuesAs(
            new EventAuditRecordParameters(ACL_UPDATE, CREDENTIAL_NAME, READ_ACL, "Kirk")
        )));
  }
}
