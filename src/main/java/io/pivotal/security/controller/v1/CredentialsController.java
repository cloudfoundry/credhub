package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.audit.EventAuditLogService;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.handler.CredentialsHandler;
import io.pivotal.security.handler.GenerateHandler;
import io.pivotal.security.handler.RegenerateHandler;
import io.pivotal.security.handler.SetHandler;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.CredentialRegenerateRequest;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.util.StringUtil;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static java.util.Collections.singletonList;

@RestController
@RequestMapping(
    path = CredentialsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CredentialsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(CredentialsController.class);
  private final PermissionedCredentialService credentialService;
  private final EventAuditLogService eventAuditLogService;
  private final ObjectMapper objectMapper;
  private final SetHandler setHandler;
  private final GenerateHandler generateHandler;
  private final RegenerateHandler regenerateHandler;
  private final CredentialsHandler credentialsHandler;

  @Autowired
  public CredentialsController(PermissionedCredentialService credentialService,
      EventAuditLogService eventAuditLogService,
      ObjectMapper objectMapper,
      GenerateHandler generateHandler,
      RegenerateHandler regenerateHandler,
      CredentialsHandler credentialsHandler,
      SetHandler setHandler) {
    this.credentialService = credentialService;
    this.eventAuditLogService = eventAuditLogService;
    this.objectMapper = objectMapper;
    this.generateHandler = generateHandler;
    this.regenerateHandler = regenerateHandler;
    this.credentialsHandler = credentialsHandler;
    this.setHandler = setHandler;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView generate(InputStream inputStream) throws IOException {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return auditedHandlePostRequest(requestInputStream);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView set(@RequestBody BaseCredentialSetRequest requestBody) {
    requestBody.validate();

    try {
      return auditedHandlePutRequest(requestBody);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void delete(@RequestParam(value = "name") String credentialName) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    eventAuditLogService.auditEvents((eventAuditRecordParametersList) -> {
      credentialsHandler.deleteCredential(credentialName, eventAuditRecordParametersList);
      return true;
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView getCredentialById(@PathVariable String id) {
    return eventAuditLogService.auditEvents(eventAuditRecordParametersList -> {
      CredentialVersion credentialVersionVersion = credentialsHandler
          .getCredentialVersionByUUID(id, eventAuditRecordParametersList);
      return CredentialView.fromEntity(credentialVersionVersion);
    });
  }

  @GetMapping(path = "")
  @ResponseStatus(HttpStatus.OK)
  public DataResponse getCredential(
      @RequestParam(value = "name") String credentialName,
      @RequestParam(value = "versions", required = false) Integer numberOfVersions,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current
  ) {
    if (StringUtils.isEmpty(credentialName)) {
      throw new InvalidQueryParameterException("error.missing_query_parameter", "name");
    }

    return eventAuditLogService.auditEvents(eventAuditRecordParametersList -> {
      List<CredentialVersion> credentialVersions;
      if (current) {
        CredentialVersion credentialVersion = credentialsHandler
            .getMostRecentCredentialVersion(credentialName, eventAuditRecordParametersList);
        credentialVersions = singletonList(credentialVersion);
      } else {
        credentialVersions = credentialsHandler.getNCredentialVersions(credentialName, numberOfVersions,
            eventAuditRecordParametersList);
      }

      return DataResponse.fromEntity(credentialVersions);
    });
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(@RequestParam("path") String path) {
    return eventAuditLogService
        .auditEvents(eventAuditRecordParametersList -> new FindCredentialResults(credentialService.findStartingWithPath(path, eventAuditRecordParametersList)));
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindPathResults findPaths() {
    return eventAuditLogService.auditEvents(eventAuditRecordParametersList -> {
      List<String> paths = credentialService.findAllPaths(eventAuditRecordParametersList);
      return FindPathResults.fromEntity(paths);
    });
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByNameLike(@RequestParam("name-like") String nameLike) {
    return eventAuditLogService
        .auditEvents(eventAuditRecordParametersList -> new FindCredentialResults(credentialService.findContainingName(nameLike, eventAuditRecordParametersList)));
  }

  private CredentialView auditedHandlePostRequest(InputStream inputStream) {
    return eventAuditLogService
        .auditEvents((auditRecordParameters -> {
          return deserializeAndHandlePostRequest(
              inputStream,
              auditRecordParameters
          );
        }));
  }

  private CredentialView deserializeAndHandlePostRequest(
      InputStream inputStream,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    try {
      String requestString = StringUtil.fromInputStream(inputStream);

      if (readRegenerateFlagFrom(requestString)) {
        return handleRegenerateRequest(requestString, auditRecordParameters);
      } else {
        return handleGenerateRequest(auditRecordParameters, requestString
        );
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private CredentialView handleGenerateRequest(
      List<EventAuditRecordParameters> auditRecordParameters,
      String requestString
  ) throws IOException {
    BaseCredentialGenerateRequest requestBody = objectMapper
        .readValue(requestString, BaseCredentialGenerateRequest.class);
    requestBody.validate();

    return generateHandler.handle(requestBody, auditRecordParameters);
  }

  private CredentialView handleRegenerateRequest(
      String requestString, List<EventAuditRecordParameters> auditRecordParameters
  ) throws IOException {
    CredentialRegenerateRequest requestBody = objectMapper
        .readValue(requestString, CredentialRegenerateRequest.class);

    return regenerateHandler
        .handleRegenerate(requestBody.getName(), auditRecordParameters);
  }

  private CredentialView auditedHandlePutRequest(@RequestBody BaseCredentialSetRequest requestBody) {
    return eventAuditLogService.auditEvents(auditRecordParameters ->
        handlePutRequest(requestBody, auditRecordParameters));
  }

  private CredentialView handlePutRequest(
      @RequestBody BaseCredentialSetRequest requestBody,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    return setHandler.handle(
        requestBody,
        auditRecordParameters
    );
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
}
