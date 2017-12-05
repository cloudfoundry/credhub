package org.cloudfoundry.credhub.auth;

import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

@Component
@RequestScope
public class UserContextHolder {
  private UserContext userContext;

  public UserContext getUserContext() {
    return userContext;
  }

  public void setUserContext(UserContext userContext) {
    this.userContext = userContext;
  }
}
