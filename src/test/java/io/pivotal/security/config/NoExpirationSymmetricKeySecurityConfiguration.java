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

  public static final String VALID_SYMMETRIC_KEY_JWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2Fj"
      + "eS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYjJl"
      + "YWE3YiIsInN1YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbImN"
      + "yZWRodWIucmVhZCIsImNyZWRodWIud3JpdGUiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNyZW"
      + "RodWIiLCJhenAiOiJjcmVkaHViIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjFjYzQ5N"
      + "zJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6ImNy"
      + "ZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZSI6MjczNzMwNDc3MywicmV2X3N"
      + "pZyI6ImU1NGFiMzlhIiwiaWF0IjoyNzM3MzA0NzUzLCJleHAiOjI3MzczMDQ3NzMsImlzcyI6Imh0dHBzOi"
      + "8vNTIuMjA0LjQ5LjEwNzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImNyZWRodWIiX"
      + "X0.aYg-9v_GLTqEYV8fGJd_ilMwYLsqXQtJFVCl5cMXrcM";
  public static final String EXPIRED_SYMMETRIC_KEY_JWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2"
      + "FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYj"
      + "JlYWE3YiIsInN1YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbI"
      + "mNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNy"
      + "ZWRodWIiLCJhenAiOiJjcmVkaHViIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjFjYzQ"
      + "5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6Im"
      + "NyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZSI6MTQ2OTA1MTcwNCwicmV2X"
      + "3NpZyI6ImU1NGFiMzlhIiwiaWF0IjoxNDY5MDUxNzA0LCJleHAiOjE0NjkwNTE4MjQsImlzcyI6Imh0dHBz"
      + "Oi8vNTIuMjA0LjQ5LjEwNzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImNyZWRodWI"
      + "iXX0.URLLvIo5BVzCfcBBEgZpnTje6iY3F2ygE7CpC5u480g";
  public static final String INVALID_SYMMETRIC_KEY_JWT = "kyJhbGciOiJIUzI1NiIsImtpZCI6ImxlZ2"
      + "FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMxZjZkYj"
      + "JlYWE3YiIsInN1YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3BlIjpbI"
      + "mNyZWRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNy"
      + "ZWRodWIiLCJhenAiOiJjcmVkaHViIiwiZ3JhbnRfdHlwZSI6InBhc3N3b3JkIiwidXNlcl9pZCI6IjFjYzQ"
      + "5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsIm9yaWdpbiI6InVhYSIsInVzZXJfbmFtZSI6Im"
      + "NyZWRodWJfY2xpIiwiZW1haWwiOiJjcmVkaHViX2NsaSIsImF1dGhfdGltZSI6MTQ2OTA1MTcwNCwicmV2X"
      + "3NpZyI6ImU1NGFiMzlhIiwiaWF0IjoxNDY5MDUxNzA0LCJleHAiOjE0NjkwNTE4MjQsImlzcyI6Imh0dHBz"
      + "Oi8vNTIuMjA0LjQ5LjEwNzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXVkIjpbImNyZWRodWI"
      + "iXX0.URLLvIo5BVzCfcBBEgZpnTje6iY3F2ygE7CpC5u480g";
  public static final String INVALID_SCOPE_SYMMETRIC_KEY_JWT = "eyJhbGciOiJIUzI1NiIsImtpZCI6"
      + "ImxlZ2FjeS10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiJiOTc3NzIxNGI1ZDM0Zjc4YTJlMWMx"
      + "ZjZkYjJlYWE3YiIsInN1YiI6IjFjYzQ5NzJmLTE4NGMtNDU4MS05ODdiLTg1YjdkOTdlOTA5YyIsInNjb3B"
      + "lIjpbImNyZWRodWIuYmFkX3Njb3BlIl0sImNsaWVudF9pZCI6ImNyZWRodWIiLCJjaWQiOiJjcmVkaHViIi"
      + "wiYXpwIjoiY3JlZGh1YiIsImdyYW50X3R5cGUiOiJwYXNzd29yZCIsInVzZXJfaWQiOiIxY2M0OTcyZi0xO"
      + "DRjLTQ1ODEtOTg3Yi04NWI3ZDk3ZTkwOWMiLCJvcmlnaW4iOiJ1YWEiLCJ1c2VyX25hbWUiOiJjcmVkaHVi"
      + "X2NsaSIsImVtYWlsIjoiY3JlZGh1Yl9jbGkiLCJhdXRoX3RpbWUiOjI3MzczMDQ3NzMsInJldl9zaWciOiJ"
      + "lNTRhYjM5YSIsImlhdCI6MjczNzMwNDc1MywiZXhwIjoyNzM3MzA0NzczLCJpc3MiOiJodHRwczovLzUyLj"
      + "IwNC40OS4xMDc6ODQ0My9vYXV0aC90b2tlbiIsInppZCI6InVhYSIsImF1ZCI6WyJjcmVkaHViIl19.M2C5"
      + "iZEdD3gPsmt9L_E73qYCPg_eYYvfPHYka2G3zsA";
  public static final String INVALID_SIGNATURE_JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS"
      + "10b2tlbi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJqdGkiOiIyOGQwZWIxMjZiMGQ0YTJjOTY5NDA4NjRiZGFjNW"
      + "MyNiIsInN1YiI6IjhmOTMzYWYwLTU2MzAtNDE5Ni1iODdhLWQ1NmEzMzlmYjMwNSIsInNjb3BlIjpbImNyZ"
      + "WRodWIud3JpdGUiLCJjcmVkaHViLnJlYWQiXSwiY2xpZW50X2lkIjoiY3JlZGh1YiIsImNpZCI6ImNyZWRo"
      + "dWIiLCJhenAiOiJjcmVkaHViIiwicmV2b2NhYmxlIjp0cnVlLCJncmFudF90eXBlIjoicGFzc3dvcmQiLCJ"
      + "1c2VyX2lkIjoiOGY5MzNhZjAtNTYzMC00MTk2LWI4N2EtZDU2YTMzOWZiMzA1Iiwib3JpZ2luIjoidWFhIi"
      + "widXNlcl9uYW1lIjoiY3JlZGh1Yl9jbGkiLCJlbWFpbCI6ImNyZWRodWJfY2xpIiwiYXV0aF90aW1lIjoxN"
      + "Dc5MTY1MjkwLCJyZXZfc2lnIjoiNGI0MzViYjYiLCJpYXQiOjE0NzkxNjUyOTAsImV4cCI6MTQ3OTE2NTQx"
      + "MCwiaXNzIjoiaHR0cHM6Ly81MC4xNy41OS42Nzo4NDQzL29hdXRoL3Rva2VuIiwiemlkIjoidWFhIiwiYXV"
      + "kIjpbImNyZWRodWIiXX0.H1iX_B3ORGVCUtN3fMeN-PoDvj4tD6M47M1wSiLARIt68Puwa40SnaSpu9Zwyt"
      + "6RgoAB3QCByl-vMW_eubSY6rHXl7A47cOTlBn8mAJ66H5hSjhNhXB7OZicfD0I0scWH0xwCPALLj8m7uY3D"
      + "GG28XKNM-19AwZXo_vE1KJ3JOndPAhe-uoKq7oeUWLx7PNbWSmsqCYPP5PkMEtlNT_XQYSJ-1UIVL5fogFh"
      + "5vNT365GsSSmcHIQX6q0cDssDl3zBz_f-544jQyfZRKQlGp9LcrRDSh9aVnKGe_ayRt3Xlala43pg68Fmu-"
      + "hdA02HTjVwtDDjCCmNLKEVdOlcRbh0g";
  // Encode/decode at https://jwt.io
  private static final String SIGNING_KEY = "tokenkey";

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
