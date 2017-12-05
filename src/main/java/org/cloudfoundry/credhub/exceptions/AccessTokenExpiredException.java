package org.cloudfoundry.credhub.exceptions;

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;

public class AccessTokenExpiredException extends ClientAuthenticationException {

  public AccessTokenExpiredException(String msg, Throwable t) {
    super(msg, t);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "access_token_expired";
  }

  @Override
  public int getHttpErrorCode() {
    return 401;
  }
}
