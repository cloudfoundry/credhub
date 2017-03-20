package io.pivotal.security.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

public class UserContext {
  public static final String VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE = null;

  private String userId = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String userName = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String issuer = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private long validFrom = Instant.EPOCH.getEpochSecond();
  private long validUntil = Instant.EPOCH.getEpochSecond();
  private String clientId;
  private String scope = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String grantType = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE;
  private String authMethod;
  private Collection<? extends GrantedAuthority> authorities;


  public static UserContext fromAuthentication (Authentication authentication, String token, ResourceServerTokenServices tokenServices){
    if (authentication instanceof OAuth2Authentication)
       return fromOauth((OAuth2Authentication) authentication, token, tokenServices);
    else
      return fromMtls((PreAuthenticatedAuthenticationToken) authentication);
  }

  private static UserContext fromOauth(OAuth2Authentication authentication, String token, ResourceServerTokenServices tokenServices){
    UserContext user = new UserContext();
    OAuth2AccessToken accessToken;
    OAuth2Request oAuth2Request = authentication.getOAuth2Request();
    user.authMethod = "uaa";
    user.clientId = oAuth2Request.getClientId();
    user.grantType = oAuth2Request.getGrantType();
    user.authorities = authentication.getAuthorities();

    if (token == null) {
      OAuth2AuthenticationDetails authDetails = (OAuth2AuthenticationDetails) authentication.getDetails();
      token = authDetails.getTokenValue();
    }

    accessToken = tokenServices.readAccessToken(token);

    if (accessToken != null) {
      Set<String> scopes = accessToken.getScope();
      user.scope = scopes == null ? null : String.join(",", scopes);

      Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();
      user.userName = (String) additionalInformation.get("user_name");
      user.userId = (String) additionalInformation.get("user_id");
      user.issuer = (String) additionalInformation.get("iss");
      user.validFrom = claimValueAsLong(additionalInformation, "iat");
      user.validUntil = accessToken.getExpiration().toInstant().getEpochSecond();
    }

   return user;
  }

  private static UserContext fromMtls (PreAuthenticatedAuthenticationToken authentication){
    UserContext user = new UserContext();

    X509Certificate certificate = (X509Certificate) authentication.getCredentials();

    user.authMethod = "mutual_tls";
    user.authorities = authentication.getAuthorities();
    user.validFrom =  certificate.getNotBefore().toInstant().getEpochSecond();
    user.validUntil = certificate.getNotAfter().toInstant().getEpochSecond();
    user.clientId = certificate.getSubjectDN().getName();

    return user;
  }


  public String getUserName(){
    return userName;
  }

  public String getUserId() {
    return userId;
  }

  public String getIssuer() {
    return issuer;
  }

  public long getValidFrom() {
    return validFrom;
  }

  public long getValidUntil() {
    return validUntil;
  }

  public String getClientId() {
    return clientId;
  }

  public String getScope() {
    return scope;
  }

  public String getGrantType() {
    return grantType;
  }

  public String getAuthMethod() {
    return authMethod;
  }

  public Collection<? extends GrantedAuthority> getAuthorities(){
    return authorities;
  }

  /*
   * The "iat" and "exp" claims are parsed by Jackson as integers, because JWT defines these
   * as seconds since Epoch (https://tools.ietf.org/html/rfc7519#section-2). That means it has a
   * Year-2038 bug. To adapt to our local model, hoping JWT will some day be improved, this
   * function returns a numeric value as long.
   */
  private static long claimValueAsLong(Map<String, Object> additionalInformation, String claimName) {
    return ((Number) additionalInformation.get(claimName)).longValue();
  }
}

