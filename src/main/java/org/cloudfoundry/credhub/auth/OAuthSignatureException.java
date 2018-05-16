package org.cloudfoundry.credhub.auth;

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;

public class OAuthSignatureException extends ClientAuthenticationException {
  public OAuthSignatureException(String msg) {
    super(msg);
  }

  @Override
  public int getHttpErrorCode() {
    return 401;
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "invalid_token";
  }
}
