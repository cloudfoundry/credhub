package io.pivotal.security.controller.v1.credential;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.handler.CredentialHandler;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.service.SetService;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResult;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(
    path = CredentialsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CredentialsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(CredentialsController.class);
  private final CredentialDataService credentialDataService;
  private final EventAuditLogService eventAuditLogService;
  private final ObjectMapper objectMapper;
  private final GenerateService generateService;
  private final SetService setService;
  private final RegenerateService regenerateService;
  private final PermissionService permissionService;
  private final CredentialHandler credentialHandler;

  @Autowired
  public CredentialsController(CredentialDataService credentialDataService,
                               EventAuditLogService eventAuditLogService,
                               ObjectMapper objectMapper,
                               GenerateService generateService,
                               SetService setService,
                               RegenerateService regenerateService,
                               PermissionService permissionService,
                               CredentialHandler credentialHandler
  ) {
    this.credentialDataService = credentialDataService;
    this.eventAuditLogService = eventAuditLogService;
    this.objectMapper = objectMapper;
    this.generateService = generateService;
    this.setService = setService;
    this.regenerateService = regenerateService;
    this.permissionService = permissionService;
    this.credentialHandler = credentialHandler;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView generate(InputStream inputStream,
                                 RequestUuid requestUuid,
                                 UserContext userContext,
                                 AccessControlEntry currentUserAccessControlEntry) throws IOException {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return auditedHandlePostRequest(requestInputStream, requestUuid, userContext,
          currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView set(@RequestBody BaseCredentialSetRequest requestBody,
                            RequestUuid requestUuid,
                            UserContext userContext,
                            AccessControlEntry currentUserAccessControlEntry) {
    requestBody.validate();

    try {
      return auditedHandlePutRequest(requestBody, requestUuid, userContext,
          currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(
      @RequestParam(value = "name") String credentialName,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    eventAuditLogService.auditEvent(requestUuid, userContext, (eventAuditRecordParameters) -> {
      eventAuditRecordParameters.setCredentialName(credentialName);
      eventAuditRecordParameters.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_DELETE);

      credentialHandler.deleteCredential(credentialName);

      return true;
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView getCredentialById(
      @PathVariable String id,
      RequestUuid requestUuid,
      UserContext userContext) {

    return CredentialView.fromEntity(retrieveCredentialWithAuditing(
        id,
        findAsList(credentialDataService::findByUuid),
        requestUuid,
        userContext
    ).get(0));
  }

  @GetMapping(path = "")
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getCredential(
      @RequestParam(value = "name") String credentialName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      RequestUuid requestUuid,
      UserContext userContext) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    return DataResponse.fromEntity(retrieveCredentialWithAuditing(
        credentialName,
        selectLookupFunction(current),
        requestUuid,
        userContext
    ));
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(
      @RequestParam("path") String path,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    return findWithAuditing(path, credentialDataService::findStartingWithPath, requestUuid, userContext);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindPathResults findPaths(RequestUuid requestUuid, UserContext userContext) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
      eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_FIND);
      List<String> paths = credentialDataService.findAllPaths();
      return FindPathResults.fromEntity(paths);
    });
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByNameLike(
      @RequestParam("name-like") String nameLike,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    return findWithAuditing(nameLike, credentialDataService::findContainingName, requestUuid,
        userContext);
  }

  private CredentialView auditedHandlePostRequest(
      InputStream inputStream,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService
        .auditEvent(requestUuid, userContext, (auditRecordParameters -> {
          return deserializeAndHandlePostRequest(
              inputStream,
              auditRecordParameters,
              currentUserAccessControlEntry);
        }));
  }

  private CredentialView deserializeAndHandlePostRequest(
      InputStream inputStream,
      EventAuditRecordParameters eventAuditRecordParameters,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    try {
      String requestString = IOUtils.toString(new InputStreamReader(inputStream));
      boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

      if (isRegenerateRequest) {
        // If it's a regenerate request deserialization is simple; the generation case requires
        // polymorphic deserialization See BaseCredentialGenerateRequest to see how that's done. It
        // would be nice if Jackson could pick a subclass based on an arbitrary function, since
        // we want to consider both type and .regenerate. We could do custom deserialization but
        // then we'd have to do the entire job by hand.
        return handleRegenerateRequest(eventAuditRecordParameters, requestString,
            currentUserAccessControlEntry);
      } else {
        return handleGenerateRequest(eventAuditRecordParameters, requestString,
            currentUserAccessControlEntry);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(
      EventAuditRecordParameters eventAuditRecordParameters,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    BaseCredentialGenerateRequest requestBody = objectMapper
        .readValue(requestString, BaseCredentialGenerateRequest.class);
    requestBody.validate();

    return generateService
        .performGenerate(eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private CredentialView handleRegenerateRequest(
      EventAuditRecordParameters eventAuditRecordParameters,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    CredentialRegenerateRequest requestBody = objectMapper
        .readValue(requestString, CredentialRegenerateRequest.class);

    return regenerateService
        .performRegenerate(eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private CredentialView auditedHandlePutRequest(
      @RequestBody BaseCredentialSetRequest requestBody,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters ->
        handlePutRequest(requestBody, eventAuditRecordParameters, currentUserAccessControlEntry));
  }

  private CredentialView handlePutRequest(
      @RequestBody BaseCredentialSetRequest requestBody,
      EventAuditRecordParameters eventAuditRecordParameters,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return setService
        .performSet(eventAuditRecordParameters, requestBody, currentUserAccessControlEntry);
  }

  private Function<String, List<Credential>> selectLookupFunction(boolean current) {
    if (current) {
      return findAsList(credentialDataService::findMostRecent);
    } else {
      return credentialDataService::findAllByName;
    }
  }

  private Function<String, List<Credential>> findAsList(Function<String, Credential> finder) {
    return (toFind) -> {
      Credential credential = finder.apply(toFind);
      return credential != null ? newArrayList(credential) : newArrayList();
    };
  }

  private List<Credential> retrieveCredentialWithAuditing(String identifier,
                                                          Function<String, List<Credential>> finder,
                                                          RequestUuid requestUuid,
                                                          UserContext userContext) {
    return eventAuditLogService.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
      eventAuditRecordParameters.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);
          try {
            List<Credential> credentials = finder.apply(identifier);
            if (!credentials.isEmpty()) {
              final CredentialName credentialName = credentials.get(0).getCredentialName();
              eventAuditRecordParameters.setCredentialName(credentialName.getName());
              //The permission check is done this late to allow the audit log to distinguish between
              //404s caused by permission errors and actual 404s.
              permissionService.verifyReadPermission(userContext, credentialName);
              return credentials;
            } else {
              throw new EntryNotFoundException("error.credential_not_found");
            }
          } catch (PermissionException e) {
            throw new EntryNotFoundException("error.credential_not_found");
          }
        });
  }

  private boolean readRegenerateFlagFrom(String requestString) {
    boolean isRegenerateRequest;
    try {
      isRegenerateRequest = JsonPath.read(requestString, "$.regenerate");
    } catch (PathNotFoundException e) {
      // could have just returned null, that would have been pretty useful
      isRegenerateRequest = false;
    }
    return isRegenerateRequest;
  }

  private FindCredentialResults findWithAuditing(String nameSubstring,
      Function<String, List<FindCredentialResult>> finder,
      RequestUuid requestUuid,
      UserContext userContext) {
    return eventAuditLogService
        .auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
          eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_FIND);
          return new FindCredentialResults(finder.apply(nameSubstring));
        });
  }
}
