package org.cloudfoundry.credhub.utils

import org.bouncycastle.crypto.CryptoServicesRegistrar
import org.bouncycastle.crypto.EntropySourceProvider
import org.bouncycastle.crypto.fips.FipsDRBG
import org.bouncycastle.crypto.util.BasicEntropySourceProvider
import org.bouncycastle.util.Pack
import java.security.SecureRandom

/**
 * The following configuration is based on the examples and code from
 * [Bouncy Castle docs](https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf)
 * and [org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider].
 */
class BouncyCastleFipsConfigurer {
    companion object {
        @JvmStatic
        fun configure() {
            CryptoServicesRegistrar.setApprovedOnlyMode(true)

            val nonBlockingSecureRandom = SecureRandom.getInstance(
                "NativePRNGNonBlocking",
            )
            val entSource: EntropySourceProvider = BasicEntropySourceProvider(
                nonBlockingSecureRandom,
                true,
            )

            val drgbBldr = FipsDRBG.SHA512.fromEntropySource(entSource)
                .setSecurityStrength(256)
                .setEntropyBitsRequired(256)
                .setPersonalizationString(
                    "Credhub FIPS default padder".toByteArray(),
                )

            CryptoServicesRegistrar.setSecureRandom(
                drgbBldr.build(
                    Pack.longToBigEndian(System.currentTimeMillis()),
                    true,
                ),
            )
        }
    }
}
