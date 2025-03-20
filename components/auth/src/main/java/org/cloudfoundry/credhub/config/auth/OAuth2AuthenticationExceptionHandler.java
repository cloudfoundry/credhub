package org.cloudfoundry.credhub.config.auth;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.nimbusds.jose.shaded.gson.JsonObject;

/**
 * Customized BearerTokenAuthenticationEntryPoint to fill the response body
 * with json error data when an OAuth2AuthenticationException occurs.
 */
public class OAuth2AuthenticationExceptionHandler
        implements AuthenticationEntryPoint {
    private BearerTokenAuthenticationEntryPoint btaep =
            new BearerTokenAuthenticationEntryPoint();

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException {
        btaep.commence(request, response, authException);
        var jsonObject = new JsonObject();
        if (authException instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();
            jsonObject.addProperty("error", error.getErrorCode());
            jsonObject.addProperty("error_description", error.getDescription());
        } else if (authException instanceof InsufficientAuthenticationException) {
            jsonObject.addProperty("error", OAuth2ErrorCodes.ACCESS_DENIED);
            jsonObject.addProperty("error_description", authException.getMessage());
        }
        response.setContentType("application/json");
        try (PrintWriter writer = response.getWriter()) {
            writer.write(jsonObject.toString());
            writer.flush();
        }
    }
}
