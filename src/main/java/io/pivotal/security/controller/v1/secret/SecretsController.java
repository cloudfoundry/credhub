package io.pivotal.security.controller.v1.secret;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordBuilder;
import io.pivotal.security.audit.RequestUuid;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.RegenerateService;
import io.pivotal.security.service.SetService;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.SecretView;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import java.util.function.Function;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_FIND;

@RestController
@RequestMapping(
    path = SecretsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(SecretsController.class);
  private final SecretDataService secretDataService;
  private final EventAuditLogService eventAuditLogService;
  private final ObjectMapper objectMapper;
  private final GenerateService generateService;
  private final SetService setService;
  private final RegenerateService regenerateService;
  private final PermissionService permissionService;

  @Autowired
  public SecretsController(SecretDataService secretDataService,
      EventAuditLogService eventAuditLogService,
      ObjectMapper objectMapper,
      GenerateService generateService,
      SetService setService,
      RegenerateService regenerateService,
      PermissionService permissionService
  ) {
    this.secretDataService = secretDataService;
    this.eventAuditLogService = eventAuditLogService;
    this.objectMapper = objectMapper;
    this.generateService = generateService;
    this.setService = setService;
    this.regenerateService = regenerateService;
    this.permissionService = permissionService;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public SecretView generate(InputStream inputStream,
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
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public SecretView set(@RequestBody BaseSecretSetRequest requestBody,
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
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody, requestUuid, userContext,
          currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(
      @RequestParam(value = "name") String secretName,
      RequestUuid requestUuid,
      UserContext userContext
  ) {
    if (StringUtils.isEmpty(secretName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    eventAuditLogService.performWithAuditing(requestUuid, userContext, (eventAuditRecordBuilder) -> {
      eventAuditRecordBuilder.setCredentialName(secretName);
      eventAuditRecordBuilder.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_DELETE);

      boolean deleteSucceeded = secretDataService.delete(secretName);

      if (!deleteSucceeded) {
        throw new EntryNotFoundException("error.credential_not_found");
      }

      return true;
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public SecretView getSecretById(
      @PathVariable String id,
      RequestUuid requestUuid,
      UserContext userContext) {

    return SecretView.fromEntity(retrieveSecretWithAuditing(
        id,
        findAsList(secretDataService::findByUuid),
        requestUuid,
        userContext
    ).get(0));
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      RequestUuid requestUuid,
      UserContext userContext) {

    return DataResponse.fromEntity(retrieveSecretWithAuditing(
        secretName,
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
    return findWithAuditing(path, secretDataService::findStartingWithPath, requestUuid, userContext);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindPathResults findPaths(RequestUuid requestUuid, UserContext userContext) {
    return eventAuditLogService.performWithAuditing(requestUuid, userContext, eventAuditRecordBuilder -> {
      eventAuditRecordBuilder.setAuditingOperationCode(CREDENTIAL_FIND);
      List<String> paths = secretDataService.findAllPaths();
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
    return findWithAuditing(nameLike, secretDataService::findContainingName, requestUuid,
        userContext);
  }

  private SecretView auditedHandlePostRequest(
      InputStream inputStream,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService
        .performWithAuditing(requestUuid, userContext, (eventAuditRecordBuilder -> {
          return deserializeAndHandlePostRequest(
              inputStream,
              eventAuditRecordBuilder,
              currentUserAccessControlEntry);
        }));
  }

  private SecretView deserializeAndHandlePostRequest(
      InputStream inputStream,
      EventAuditRecordBuilder eventAuditRecordBuilder,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    try {
      String requestString = IOUtils.toString(new InputStreamReader(inputStream));
      boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

      if (isRegenerateRequest) {
        // If it's a regenerate request deserialization is simple; the generation case requires
        // polymorphic deserialization See BaseSecretGenerateRequest to see how that's done. It
        // would be nice if Jackson could pick a subclass based on an arbitrary function, since
        // we want to consider both type and .regenerate. We could do custom deserialization but
        // then we'd have to do the entire job by hand.
        return handleRegenerateRequest(eventAuditRecordBuilder, requestString,
            currentUserAccessControlEntry);
      } else {
        return handleGenerateRequest(eventAuditRecordBuilder, requestString,
            currentUserAccessControlEntry);
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private SecretView handleGenerateRequest(
      EventAuditRecordBuilder auditRecordBuilder,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    BaseSecretGenerateRequest requestBody = objectMapper
        .readValue(requestString, BaseSecretGenerateRequest.class);
    requestBody.validate();

    return generateService
        .performGenerate(auditRecordBuilder, requestBody, currentUserAccessControlEntry);
  }

  private SecretView handleRegenerateRequest(
      EventAuditRecordBuilder auditRecordBuilder,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    SecretRegenerateRequest requestBody = objectMapper
        .readValue(requestString, SecretRegenerateRequest.class);

    return regenerateService
        .performRegenerate(auditRecordBuilder, requestBody, currentUserAccessControlEntry);
  }

  private SecretView auditedHandlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      RequestUuid requestUuid,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return eventAuditLogService.performWithAuditing(requestUuid, userContext, eventAuditRecordBuilder ->
        handlePutRequest(requestBody, eventAuditRecordBuilder, currentUserAccessControlEntry));
  }

  private SecretView handlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      EventAuditRecordBuilder eventAuditRecordBuilder,
      AccessControlEntry currentUserAccessControlEntry
  ) {
    return setService
        .performSet(eventAuditRecordBuilder, requestBody, currentUserAccessControlEntry);
  }

  private Function<String, List<NamedSecret>> selectLookupFunction(boolean current) {
    if (current) {
      return findAsList(secretDataService::findMostRecent);
    } else {
      return secretDataService::findAllByName;
    }
  }

  private Function<String, List<NamedSecret>> findAsList(Function<String, NamedSecret> finder) {
    return (toFind) -> {
      NamedSecret namedSecret = finder.apply(toFind);
      return namedSecret != null ? newArrayList(namedSecret) : newArrayList();
    };
  }

  private List<NamedSecret> retrieveSecretWithAuditing(String identifier,
                                                       Function<String, List<NamedSecret>> finder,
                                                       RequestUuid requestUuid,
                                                       UserContext userContext) {
    return eventAuditLogService.performWithAuditing(requestUuid, userContext, eventAuditRecordBuilder -> {
      eventAuditRecordBuilder.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);

          if (StringUtils.isEmpty(identifier)) {
            throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
          }
          try {
            List<NamedSecret> namedSecrets = finder.apply(identifier);
            if (namedSecrets.isEmpty()) {
              throw new EntryNotFoundException("error.credential_not_found");
            } else {
              String name = namedSecrets.get(0).getName();
              eventAuditRecordBuilder.setCredentialName(name);
              //The permission check is done this late to allow the audit log to distinguish between
              //404s caused by permission errors and actual 404s.
              permissionService.verifyReadPermission(userContext, identifier);
              return namedSecrets;
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
      Function<String, List<SecretView>> finder,
      RequestUuid requestUuid,
      UserContext userContext) {
    return eventAuditLogService
        .performWithAuditing(requestUuid, userContext, eventAuditRecordBuilder -> {
          eventAuditRecordBuilder.setAuditingOperationCode(CREDENTIAL_FIND);
          List<SecretView> secretViews = finder.apply(nameSubstring);
          return FindCredentialResults.fromSecrets(secretViews);
        });
  }
}
