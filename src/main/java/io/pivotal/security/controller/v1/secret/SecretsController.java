package io.pivotal.security.controller.v1.secret;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_FIND;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.request.SecretRegenerateRequest;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.service.SetService;
import io.pivotal.security.view.DataResponse;
import io.pivotal.security.view.FindCredentialResults;
import io.pivotal.security.view.FindPathResults;
import io.pivotal.security.view.SecretView;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.util.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(
    path = SecretsController.API_V1_DATA,
    produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
public class SecretsController {

  public static final String API_V1_DATA = "/api/v1/data";

  private static final Logger LOGGER = LogManager.getLogger(SecretsController.class);
  private final SecretDataService secretDataService;
  private final AuditLogService auditLogService;
  private final ObjectMapper objectMapper;
  private final GenerateService generateService;
  private final SetService setService;
  private final RegenerateService regenerateService;

  @Autowired
  public SecretsController(SecretDataService secretDataService,
                           AuditLogService auditLogService,
                           ObjectMapper objectMapper,
                           GenerateService generateService,
                           SetService setService,
                           RegenerateService regenerateService
  ) {
    this.secretDataService = secretDataService;
    this.auditLogService = auditLogService;
    this.objectMapper = objectMapper;
    this.generateService = generateService;
    this.setService = setService;
    this.regenerateService = regenerateService;
  }

  @RequestMapping(path = "", method = RequestMethod.POST)
  public ResponseEntity generate(InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry) throws Exception {
    InputStream requestInputStream = new ByteArrayInputStream(ByteStreams.toByteArray(inputStream));
    try {
      return auditedHandlePostRequest(requestInputStream, request, userContext, currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      requestInputStream.reset();
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePostRequest(requestInputStream, request, userContext, currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.PUT)
  public ResponseEntity set(@RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry) throws Exception {
    requestBody.validate();

    try {
      return auditedHandlePutRequest(requestBody, request, userContext, currentUserAccessControlEntry);
    } catch (JpaSystemException | DataIntegrityViolationException e) {
      LOGGER.error(
          "Exception \"" + e.getMessage() + "\" with class \"" + e.getClass().getCanonicalName()
              + "\" while storing secret, possibly caused by race condition, retrying...");
      return auditedHandlePutRequest(requestBody, request, userContext, currentUserAccessControlEntry);
    }
  }

  @RequestMapping(path = "", method = RequestMethod.DELETE)
  public ResponseEntity delete(
      @RequestParam(value = "name") String secretName,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    if (StringUtils.isEmpty(secretName)) {
      throw new MissingServletRequestParameterException("name", "String");
    }

    return auditLogService.performWithAuditing(auditRecorder -> {
      auditRecorder.setCredentialName(secretName);
      auditRecorder.populateFromRequest(request);
      auditRecorder.setUserContext(userContext);

      boolean deleteSucceeded = secretDataService.delete(secretName);
      if (!deleteSucceeded) {
        throw new EntryNotFoundException("error.credential_not_found");
      }

      return new ResponseEntity(HttpStatus.NO_CONTENT);
    });
  }

  @RequestMapping(path = "/{id}", method = RequestMethod.GET)
  public ResponseEntity getSecretById(
      @PathVariable String id,
      HttpServletRequest request,
      UserContext userContext) throws Exception {

    return retrieveSecretWithAuditing(
        id,
        findAsList(secretDataService::findByUuid),
        request,
        userContext,
        true
    );
  }

  @RequestMapping(path = "", method = RequestMethod.GET)
  public ResponseEntity getSecret(
      @RequestParam(value = "name", required = false) String secretName,
      @RequestParam(value = "current", required = false, defaultValue = "false") boolean current,
      HttpServletRequest request,
      UserContext userContext) throws Exception {

    return retrieveSecretWithAuditing(
        secretName,
        selectLookupFunction(current),
        request,
        userContext,
        false
    );
  }

  @RequestMapping(path = "", params = "path", method = RequestMethod.GET)
  public ResponseEntity findByPath(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return findStartingWithAuditing(params.get("path"), request, userContext);
  }

  @RequestMapping(path = "", params = "paths=true", method = RequestMethod.GET)
  public ResponseEntity findPaths(HttpServletRequest request, UserContext userContext)
      throws Exception {
    return findPathsWithAuditing(request, userContext);
  }

  @RequestMapping(path = "", params = "name-like", method = RequestMethod.GET)
  public ResponseEntity findByNameLike(
      @RequestParam Map<String, String> params,
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return findWithAuditing(params.get("name-like"), secretDataService::findContainingName, request,
        userContext);
  }

  private ResponseEntity auditedHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) throws Exception {
    return auditLogService.performWithAuditing((auditRecordBuilder -> {
      return deserializeAndHandlePostRequest(
          inputStream,
          request,
          userContext,
          auditRecordBuilder,
          currentUserAccessControlEntry);
    }));
  }

  private ResponseEntity<?> deserializeAndHandlePostRequest(
      InputStream inputStream,
      HttpServletRequest request,
      UserContext userContext,
      AuditRecordBuilder auditRecordBuilder,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    String requestString = IOUtils.toString(new InputStreamReader(inputStream));
    boolean isRegenerateRequest = readRegenerateFlagFrom(requestString);

    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setUserContext(userContext);
    if (isRegenerateRequest) {
      // If it's a regenerate request deserialization is simple; the generation case requires
      // polymorphic deserialization See BaseSecretGenerateRequest to see how that's done. It
      // would be nice if Jackson could pick a subclass based on an arbitrary function, since
      // we want to consider both type and .regenerate. We could do custom deserialization but
      // then we'd have to do the entire job by hand.
      return handleRegenerateRequest(auditRecordBuilder, requestString, currentUserAccessControlEntry);
    } else {
      return handleGenerateRequest(auditRecordBuilder, requestString, currentUserAccessControlEntry);
    }
  }

  private ResponseEntity handleGenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    BaseSecretGenerateRequest requestBody = objectMapper.readValue(requestString, BaseSecretGenerateRequest.class);
    requestBody.validate();

    auditRecordBuilder.setCredentialName(requestBody.getName());
    return generateService.performGenerate(auditRecordBuilder, requestBody, currentUserAccessControlEntry);
  }

  private ResponseEntity handleRegenerateRequest(
      AuditRecordBuilder auditRecordBuilder,
      String requestString,
      AccessControlEntry currentUserAccessControlEntry
  ) throws IOException {
    SecretRegenerateRequest requestBody = objectMapper.readValue(requestString, SecretRegenerateRequest.class);

    return regenerateService.performRegenerate(auditRecordBuilder, requestBody, currentUserAccessControlEntry);
  }

  private ResponseEntity auditedHandlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext,
      AccessControlEntry currentUserAccessControlEntry
  ) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder ->
        handlePutRequest(requestBody, request, userContext, auditRecordBuilder, currentUserAccessControlEntry));
  }

  private ResponseEntity<?> handlePutRequest(
      @RequestBody BaseSecretSetRequest requestBody,
      HttpServletRequest request,
      UserContext userContext,
      AuditRecordBuilder auditRecordBuilder,
      AccessControlEntry currentUserAccessControlEntry
  ) throws Exception {
    auditRecordBuilder.setCredentialName(requestBody.getName());
    auditRecordBuilder.populateFromRequest(request);
    auditRecordBuilder.setUserContext(userContext);

    return setService.performSet(auditRecordBuilder, requestBody, currentUserAccessControlEntry);
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

  private ResponseEntity retrieveSecretWithAuditing(String identifier,
      Function<String, List<NamedSecret>> finder,
      HttpServletRequest request,
      UserContext userContext,
      boolean returnFirstEntry) throws Exception {
    return auditLogService.performWithAuditing(auditRecordBuilder -> {
      auditRecordBuilder.populateFromRequest(request);
      auditRecordBuilder.setUserContext(userContext);

      if (StringUtils.isEmpty(identifier)) {
        throw new MissingServletRequestParameterException("name", "String");
      }
      List<NamedSecret> namedSecrets = finder.apply(identifier);
      if (namedSecrets.isEmpty()) {
        throw new EntryNotFoundException("error.credential_not_found");
      } else {
        ResponseEntity success;
        auditRecordBuilder.setCredentialName(namedSecrets.get(0).getName());
        try {
          if (returnFirstEntry) {
            success = new ResponseEntity<>(SecretView.fromEntity(namedSecrets.get(0)),
                HttpStatus.OK);
          } else {
            success = new ResponseEntity<>(DataResponse.fromEntity(namedSecrets), HttpStatus.OK);
          }
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
        return success;
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

  private ResponseEntity findWithAuditing(String nameSubstring,
      Function<String, List<SecretView>> finder,
      HttpServletRequest request,
      UserContext userContext) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setUserContext(userContext);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<SecretView> secretViews = finder.apply(nameSubstring);
      return new ResponseEntity<>(FindCredentialResults.fromSecrets(secretViews), HttpStatus.OK);
    });
  }

  private ResponseEntity findPathsWithAuditing(
      HttpServletRequest request,
      UserContext userContext
  ) throws Exception {
    return auditLogService.performWithAuditing(auditParams -> {
      auditParams.populateFromRequest(request);
      auditParams.setUserContext(userContext);
      auditParams.setOperationCode(CREDENTIAL_FIND);
      List<String> paths = secretDataService.findAllPaths();
      return new ResponseEntity<>(FindPathResults.fromEntity(paths), HttpStatus.OK);
    });
  }

  private ResponseEntity findStartingWithAuditing(String path, HttpServletRequest request,
      UserContext userContext) throws Exception {
    return findWithAuditing(path, secretDataService::findStartingWithPath, request, userContext);
  }
}
