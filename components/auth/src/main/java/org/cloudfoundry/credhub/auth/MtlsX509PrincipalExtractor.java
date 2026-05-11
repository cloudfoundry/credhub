package org.cloudfoundry.credhub.auth;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/**
 * Extracts the principal from the OU attribute of the client certificate's Subject DN.
 * Cloud Foundry mTLS certificates carry the app identity as {@code OU=app:<uuid-v4>}.
 * Throws {@link BadCredentialsException} if the OU is absent or does not match the
 * expected {@code app:<uuid-v4>} format.
 */
public class MtlsX509PrincipalExtractor implements X509PrincipalExtractor {

    private static final Pattern MTLS_ID_PATTERN =
            Pattern.compile("app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}");

    @Override
    public Object extractPrincipal(X509Certificate clientCert) {
        X500Principal principal = clientCert.getSubjectX500Principal();
        String subjectDn = principal.getName(X500Principal.RFC2253);
        List<Rdn> rdns;
        try {
            rdns = new LdapName(subjectDn).getRdns();
        } catch (InvalidNameException ex) {
            throw new BadCredentialsException("Failed to parse client certificate subject DN", ex);
        }
        for (Rdn rdn : rdns) {
            if ("OU".equals(rdn.getType())) {
                String ouValue = String.valueOf(rdn.getValue());
                if (!MTLS_ID_PATTERN.matcher(ouValue).matches()) {
                    throw new BadCredentialsException(
                            "OU attribute does not match expected mTLS identity format: " + ouValue);
                }
                return ouValue;
            }
        }
        throw new BadCredentialsException(
                "No OU attribute found in client certificate subject DN: " + subjectDn);
    }
}
