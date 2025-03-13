package org.cloudfoundry.credhub.config.auth;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
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

        if (authException instanceof OAuth2AuthenticationException) {
            OAuth2Error error = ((OAuth2AuthenticationException) authException)
                    .getError();
            response.setContentType("application/json");
            var jsonObject = new JsonObject();
            jsonObject.addProperty("error", error.getErrorCode());
            jsonObject.addProperty("error_description", error.getDescription());
            try (PrintWriter writer = response.getWriter()) {
                writer.write(jsonObject.toString());
                writer.flush();
            }
        }
    }
}
