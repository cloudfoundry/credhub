package org.cloudfoundry.credhub.controller.v1;

import com.google.common.io.ByteStreams;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.audit.EventAuditLogService;
import org.cloudfoundry.credhub.exceptions.InvalidQueryParameterException;
import org.cloudfoundry.credhub.handler.CredentialsHandler;
import org.cloudfoundry.credhub.handler.LegacyGenerationHandler;
import org.cloudfoundry.credhub.handler.SetHandler;
import org.cloudfoundry.credhub.request.BaseCredentialSetRequest;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.cloudfoundry.credhub.view.DataResponse;
import org.cloudfoundry.credhub.view.FindCredentialResults;
import org.cloudfoundry.credhub.view.FindPathResults;
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

@RestController
@RequestMapping(
    path = CredentialsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class CredentialsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(CredentialsController.class);
  private final PermissionedCredentialService credentialService;
  private final EventAuditLogService eventAuditLogService;
  private final SetHandler setHandler;
  private final CredentialsHandler credentialsHandler;
  private final LegacyGenerationHandler legacyGenerationHandler;

  @Autowired
  public CredentialsController(PermissionedCredentialService credentialService,
                               EventAuditLogService eventAuditLogService,
                               CredentialsHandler credentialsHandler,
                               SetHandler setHandler, LegacyGenerationHandler legacyGenerationHandler) {
    this.credentialService = credentialService;
    this.eventAuditLogService = eventAuditLogService;
    this.credentialsHandler = credentialsHandler;
    this.setHandler = setHandler;
    this.legacyGenerationHandler = legacyGenerationHandler;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView generate(InputStream inputStream) throws IOException {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return legacyGenerationHandler.auditedHandlePostRequest(requestInputStream);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing credential, possibly caused by race condition, retrying...");
      return legacyGenerationHandler.auditedHandlePostRequest(requestInputStream);
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

    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    eventAuditLogService.auditEvents((eventAuditRecordParametersList) -> {
      credentialsHandler.deleteCredential(credentialNameWithPrependedSlash, eventAuditRecordParametersList);
      return true;
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public CredentialView getCredentialById(@PathVariable String id) {
    return eventAuditLogService.auditEvents(eventAuditRecordParametersList -> {
      return credentialsHandler.getCredentialVersionByUUID(id, eventAuditRecordParametersList);
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

    String credentialNameWithPrependedSlash = StringUtils.prependIfMissing(credentialName, "/");

    return eventAuditLogService.auditEvents(eventAuditRecordParametersList -> {
      if (current) {
        return credentialsHandler.getMostRecentCredentialVersion(credentialNameWithPrependedSlash, eventAuditRecordParametersList);
      } else {
        return credentialsHandler.getNCredentialVersions(credentialNameWithPrependedSlash, numberOfVersions, eventAuditRecordParametersList);
      }
    });
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  @ResponseStatus(HttpStatus.OK)
  public FindCredentialResults findByPath(@RequestParam("path") String path) {
    return eventAuditLogService
        .auditEvents(eventAuditRecordParametersList -> new FindCredentialResults(
            credentialService.findStartingWithPath(path, eventAuditRecordParametersList)));
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
        .auditEvents(eventAuditRecordParametersList -> new FindCredentialResults(
            credentialService.findContainingName(nameLike, eventAuditRecordParametersList)));
  }


  private CredentialView auditedHandlePutRequest(@RequestBody BaseCredentialSetRequest requestBody) {
    return eventAuditLogService.auditEvents(
        auditRecordParameters -> setHandler.handle(requestBody, auditRecordParameters));
  }


}
