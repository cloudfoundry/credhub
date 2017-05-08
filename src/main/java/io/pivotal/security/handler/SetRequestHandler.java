package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.SetService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class SetRequestHandler {

  private SetService setService;

  @Autowired
  public SetRequestHandler(SetService setService) {
    this.setService = setService;
  }

  public CredentialView handleSetRequest(UserContext userContext,
      List<EventAuditRecordParameters> eventAuditRecordParameters,
      BaseCredentialSetRequest setRequest,
      AccessControlEntry currentEntry) {

    StringGenerationParameters generationParameters = null;

    if (setRequest instanceof PasswordSetRequest) {
      generationParameters = ((PasswordSetRequest) setRequest).getGenerationParameters();
    }

    return setService.performSet(
        userContext,
        eventAuditRecordParameters,
        setRequest.getName(),
        setRequest.isOverwrite(),
        setRequest.getType(),
        generationParameters,
        setRequest.getCredentialValue(),
        setRequest.getAccessControlEntries(),
        currentEntry);
  }
}
