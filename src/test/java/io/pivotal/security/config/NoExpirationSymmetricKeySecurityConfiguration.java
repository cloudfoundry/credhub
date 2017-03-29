package io.pivotal.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@Profile("NoExpirationSymmetricKeySecurityConfiguration")
public class NoExpirationSymmetricKeySecurityConfiguration {

  // Encode/decode at https://jwt.io
  private static final String SIGNING_KEY = "tokenkey";
  public static final String EXPIRED_SYMMETRIC_KEY_JWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2FjeS10b"
      + "2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYjJlYWE3YiIsInN1"
      + "YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLC"
      + "JjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNyZWRodWIiLCJhenAiOiJjcmVkaHVi"
      + "IiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOT"
      + "dlOTA5YyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2Ns"
      + "aSIsImF1dGhfdGltZSI6MTQ2OTA1MTcwNCwicmV2X3NpZyI6ImU1NGFiMzlhIiwiaWF0IjoxNDY5MDUxNzA0LCJleH"
      + "AiOjE0NjkwNTE4MjQsImlzcyI6Imh0dHBzOi8vNTIuMjA0LjQ5LjEwNzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoi"
      + "dWFhIiwiYXVkIjpbImNyZWRodWIiXX0.URLLvIo5BVzCfcBBEgZpnTje6iY3F2ygE7CpC5u480g";
  public static final String INVALID_SYMMETRIC_KEY_JWT = "kyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2FjeS10b"
      + "2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYjJlYWE3YiIsInN1"
      + "YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLC"
      + "JjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNyZWRodWIiLCJhenAiOiJjcmVkaHVi"
      + "IiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOT"
      + "dlOTA5YyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2Ns"
      + "aSIsImF1dGhfdGltZSI6MTQ2OTA1MTcwNCwicmV2X3NpZyI6ImU1NGFiMzlhIiwiaWF0IjoxNDY5MDUxNzA0LCJleH"
      + "AiOjE0NjkwNTE4MjQsImlzcyI6Imh0dHBzOi8vNTIuMjA0LjQ5LjEwNzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoi"
      + "dWFhIiwiYXVkIjpbImNyZWRodWIiXX0.URLLvIo5BVzCfcBBEgZpnTje6iY3F2ygE7CpC5u480g";
  public static final String INVALID_SCOPE_SYMMETRIC_KEY_JWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2F"
      + "jeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYjJlYWE3Yi"
      + "IsInN1YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbImNyZWRodWIuYmFk"
      + "X3Njb3BlIl0sImNsaWVudF9pZCI6ImNyZWRodWIiLCJjaWQiOiJjcmVkaHViIiwiYXpwIjoiY3JlZGh1YiIsImdyYW"
      + "50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiIxY2M0OTcyZi0xODRjLTQ1ODEtOTg3Yi04NWI3ZDk3ZTkwOWMi"
      + "LCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX25hbWUiOiJjcmVkaHViX2NsaSIsImVtYWlsIjoiY3JlZGh1Yl9jbGkiLCJhdX"
      + "RoX3RpbWUiOjI3MzczMDQ3NzMsInJldl9zaWciOiJlNTRhYjM5YSIsImlhdCI6MjczNzMwNDc1MywiZXhwIjoyNzM3"
      + "MzA0NzczLCJpc3MiOiJodHRwczovLzUyLjIwNC40OS4xMDc6ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsIm"
      + "F1ZCI6WyJjcmVkaHViIl19.M2C5iZEdD3gPsmt9L_E73qYCPg_eYYvfPHYka2G3zsA";
  public static final String INVALID_SIGNATURE_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS10b2tlb"
      + "i1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIyOGQwZWIxMjZiMGQ0YTJjOTY5NDA4NjRiZGFjNWMyNiIsInN1YiI6"
      + "IjhmOTMzYWYwLTU2MzAtNDE5Ni1iODdhLWQ1NmEzMzlmYjMwNSIsInNjb3BlIjpbImNyZWRodWIud3JpdGUiLCJjcm"
      + "VkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNyZWRodWIiLCJhenAiOiJjcmVkaHViIiwi"
      + "cmV2b2NhYmxlIjp0cnVlLCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ1c2VyX2lkIjoiOGY5MzNhZjAtNTYzMC00MT"
      + "k2LWI4N2EtZDU2YTMzOWZiMzA1Iiwib3JpZ2luIjoidWFhIiwidXNlcl9uYW1lIjoiY3JlZGh1Yl9jbGkiLCJlbWFp"
      + "bCI6ImNyZWRodWJfY2xpIiwiYXV0aF90aW1lIjoxNDc5MTY1MjkwLCJyZXZfc2lnIjoiNGI0MzViYjYiLCJpYXQiOj"
      + "E0NzkxNjUyOTAsImV4cCI6MTQ3OTE2NTQxMCwiaXNzIjoiaHR0cHM6Ly81MC4xNy41OS42Nzo4NDQzL29hdXRoL3Rv"
      + "a2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImNyZWRodWIiXX0.H1iX_B3ORGVCUtN3fMeN-PoDvj4tD6M47M1wSiLARI"
      + "t68Puwa40SnaSpu9Zwyt6RgoAB3QCByl-vMW_eubSY6rHXl7A47cOTlBn8mAJ66H5hSjhNhXB7OZicfD0I0scWH0xw"
      + "CPALLj8m7uY3DGG28XKNM-19AwZXo_vE1KJ3JOndPAhe-uoKq7oeUWLx7PNbWSmsqCYPP5PkMEtlNT_XQYSJ-1UIVL"
      + "5fogFh5vNT365GsSSmcHIQX6q0cDssDl3zBz_f-544jQyfZRKQlGp9LcrRDSh9aVnKGe_ayRt3Xlala43pg68Fmu-h"
      + "dA02HTjVwtDDjCCmNLKEVdOlcRbh0g";

  @Bean
  @Primary
  public JwtAccessTokenConverter customJwtAccessTokenConverter() throws Exception {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    DefaultAccessTokenConverter accessTokenConverter =
        (DefaultAccessTokenConverter) jwtAccessTokenConverter
            .getAccessTokenConverter();
    accessTokenConverter.setIncludeGrantType(true);
    jwtAccessTokenConverter.setSigningKey(SIGNING_KEY);
    jwtAccessTokenConverter.afterPropertiesSet();
    return jwtAccessTokenConverter;
  }

  @Bean
  @Primary
  public TokenStore customTokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
    return new JwtTokenStore(jwtAccessTokenConverter);
  }

  @Bean
  @Primary
  ResourceServerTokenServices customTokenServices(TokenStore tokenStore) throws Exception {
    return new NoExpirationTokenServices(tokenStore);
  }

  static class NoExpirationTokenServices implements ResourceServerTokenServices {

    private final TokenStore tokenStore;

    NoExpirationTokenServices(TokenStore tokenStore) throws Exception {
      this.tokenStore = tokenStore;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken)
        throws AuthenticationException, InvalidTokenException {
      return tokenStore.readAuthentication(accessToken);
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessToken) {
      return tokenStore.readAccessToken(accessToken);
    }
  }
}
