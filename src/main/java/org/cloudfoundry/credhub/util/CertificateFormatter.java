package org.cloudfoundry.credhub.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;

public class CertificateFormatter {

  public static final String SSH_RSA = "ssh-rsa";

  public static String pemOf(Object pemObject) throws IOException {
    StringWriter sw = new StringWriter();
    JcaPEMWriter writer = new JcaPEMWriter(sw);
    writer.writeObject(pemObject);
    writer.close();
    return sw.toString();
  }

  // Bouncy Castle wouldn't do this for us. We got this algorithm for encoding DER from:
  // http://stackoverflow.com/questions/36382913/how-to-do-i-convert-the-publickey-to-openssh-authorized-keys-format
  // DER is also known as ASN.1 encoding.
  public static String derOf(RSAPublicKey publicKey) throws IOException {
    RSAPublicKey rsaPublicKey = publicKey;
    ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    DataOutputStream dataStream = new DataOutputStream(byteStream);

    writeBytesToDataStream(SSH_RSA.getBytes(StringUtil.UTF_8), dataStream);
    writeBytesToDataStream(rsaPublicKey.getPublicExponent().toByteArray(), dataStream);
    writeBytesToDataStream(rsaPublicKey.getModulus().toByteArray(), dataStream);

    String publicKeyEncoded = new String(Base64.encodeBase64(byteStream.toByteArray()), StringUtil.UTF_8);
    return SSH_RSA + " " + publicKeyEncoded;
  }

  private static void writeBytesToDataStream(byte[] bytes, DataOutputStream dataStream)
      throws IOException {
    dataStream.writeInt(bytes.length);
    dataStream.write(bytes);
  }

}
