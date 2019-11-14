package org.cloudfoundry.credhub.utils

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMException
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.cloudfoundry.credhub.exceptions.MalformedPrivateKeyException
import java.io.StringReader
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.RSAPublicKeySpec

class PrivateKeyReader private constructor() {
    companion object {
        @JvmStatic
        fun getPrivateKey(privateKeyPem: String): PrivateKey {
            val pemParser: PEMParser
            val parsed: Any?
            try {
                pemParser = PEMParser(StringReader(privateKeyPem))
                parsed = pemParser.readObject()
                pemParser.close()
            } catch (e: PEMException) {
                throw MalformedPrivateKeyException("Keys must be PEM-encoded PKCS#1 or unencrypted PKCS#8 keys.")
            }

            return when (parsed) {
                // PKCS1
                is PEMKeyPair -> JcaPEMKeyConverter().getPrivateKey(parsed.privateKeyInfo)
                // PKCS8
                is PrivateKeyInfo -> JcaPEMKeyConverter().getPrivateKey(parsed)
                else -> throw MalformedPrivateKeyException("Key file is not in PKCS#1 or unencrypted PKCS#8 format")
            } as? RSAPrivateKey ?: throw MalformedPrivateKeyException("Key file does not contain an RSA private key")
        }

        @JvmStatic
        fun getPublicKey(privateKeyPem: String): PublicKey {
            val privateKey = getPrivateKey(privateKeyPem) as RSAPrivateCrtKey
            val publicKeySpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)

            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(publicKeySpec)
        }
    }
}
