package org.cloudfoundry.credhub.auth;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.springframework.security.authentication.BadCredentialsException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MtlsX509PrincipalExtractorTest {

    private static final String VALID_OU = "app:12345678-1234-4123-a123-123456789012";

    private MtlsX509PrincipalExtractor extractor;
    private X509Certificate cert;

    @BeforeEach
    public void setUp() {
        extractor = new MtlsX509PrincipalExtractor();
        cert = mock(X509Certificate.class);
    }

    private void givenSubjectDn(String dn) {
        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal(dn));
    }

    @Test
    public void extractPrincipal_withValidMtlsOu_returnsPrincipal() {
        givenSubjectDn("CN=test, OU=" + VALID_OU);

        Object principal = extractor.extractPrincipal(cert);

        assertEquals(VALID_OU, principal);
    }

    @Test
    public void extractPrincipal_withNonV4UuidInOu_throwsBadCredentials() {
        // Third UUID group starts with '1' (version 1), not '4'
        givenSubjectDn("CN=test, OU=app:7e0fbd7d-14bd-11e7-a8b1-10ddb1aa64b3");

        assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
    }

    @Test
    public void extractPrincipal_withOuMissingAppPrefix_throwsBadCredentials() {
        givenSubjectDn("CN=test, OU=12345678-1234-4123-a123-123456789012");

        assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
    }

    @Test
    public void extractPrincipal_withNoOuAttribute_throwsBadCredentials() {
        givenSubjectDn("CN=test, O=org");

        assertThrows(BadCredentialsException.class, () -> extractor.extractPrincipal(cert));
    }
}
