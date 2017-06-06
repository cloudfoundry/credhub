package io.pivotal.security.service;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.InvalidJsonException;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import net.minidev.json.JSONArray;
import org.springframework.stereotype.Service;

import java.io.InvalidObjectException;
import java.util.List;
import java.util.Map;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;

@Service
public class JsonInterpolationService {

  private final JsonContextFactory jsonContextFactory;

  public JsonInterpolationService(JsonContextFactory jsonContextFactory) {
    this.jsonContextFactory = jsonContextFactory;
  }

  public DocumentContext interpolateCredhubReferences(String requestBody,
      CredentialDataService credentialDataService,
      List<EventAuditRecordParameters> eventAuditRecordParameters) throws Exception {
    DocumentContext requestJson = parseToJson(requestBody);

    Object request = requestJson.json();
    if (!(request instanceof Map)) {
      throw new InvalidJsonException();
    }

    Map<String, Object> servicesMap = (Map<String, Object>) request;
      for (Object serviceProperties : servicesMap.values()) {
        if (!(serviceProperties instanceof JSONArray)) {
          continue;
        }
        JSONArray servicePropertiesAsArray = (JSONArray) serviceProperties;
        for (Object properties : servicePropertiesAsArray) {
          if (!(properties instanceof Map)) {
            continue;
          }
          Map<String, Object> propertiesMap = (Map<String, Object>) properties;
          Object credentials = propertiesMap.get("credentials");
          if (!(credentials instanceof Map)) {
            continue;
          }
          Map<String, Object> credentialsWrapper = (Map<String, Object>) credentials;
          if (credentialsWrapper != null && credentialsWrapper.get("credhub-ref") != null) {
            Object credhubRef = credentialsWrapper.get("credhub-ref");
            if (!(credhubRef instanceof String)) {
              continue;
            }
            String credentialName = getCredentialNameFromRef((String) credhubRef);

            Credential credential = credentialDataService.findMostRecent(credentialName);
            if (credential == null) {
              throw new InvalidObjectException("error.invalid_access");
            }
            if (credential instanceof JsonCredential) {
              propertiesMap.put("credentials", ((JsonCredential) credential).getValue());
              eventAuditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_ACCESS, credential.getName()));
            } else {
              throw new ParameterizedValidationException("error.invalid_interpolation_type",
                  credentialName);
            }
          }
        }
      }
    return requestJson;
  }

  private String getCredentialNameFromRef(String credhubRef) {
    return credhubRef.replaceFirst("^\\(\\(", "").replaceFirst("\\)\\)$", "");
  }

  private DocumentContext parseToJson(String requestBody) throws Exception {
    return jsonContextFactory.getParseContext().parse(requestBody);
  }
}
