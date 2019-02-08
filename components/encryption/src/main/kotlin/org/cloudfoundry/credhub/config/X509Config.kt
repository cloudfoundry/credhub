package org.cloudfoundry.credhub.config

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509ExtensionUtils
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class X509Config {
    @Bean
    fun x509ExtensionUtils(): X509ExtensionUtils {
        return X509ExtensionUtils(JcaDigestCalculatorProviderBuilder().build().get(
            AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)))
    }
}
