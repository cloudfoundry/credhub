package org.cloudfoundry.credhub.config.auth;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import org.junit.Before;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OAuth2AuthenticationExceptionHandlerTest {

    private OAuth2AuthenticationExceptionHandler exceptionHandler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @Before
    public void setUp() {
        exceptionHandler = new OAuth2AuthenticationExceptionHandler();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void testOAuth2AuthenticationExceptionHandling() throws Exception {
        OAuth2Error error = new OAuth2Error(
                "error", "error-description", "error-uri");
        OAuth2AuthenticationException oae =
                new OAuth2AuthenticationException(error, "description");

        exceptionHandler.commence(request, response, oae);

        assertEquals(
                "{\"error\":\"error\",\"error_description\":\"error-description\"}",
                response.getContentAsString());
    }


    @Test
    public void testInsufficientAuthenticationExceptionHandling() throws Exception {
        InsufficientAuthenticationException iae
                = new InsufficientAuthenticationException("Full authentication required");

        exceptionHandler.commence(request, response, iae);

        assertEquals(
                "{\"error\":\"access_denied\",\"error_description\":\"Full authentication required\"}",
                response.getContentAsString());
    }
}
