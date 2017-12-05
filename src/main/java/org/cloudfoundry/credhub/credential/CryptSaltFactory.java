package org.cloudfoundry.credhub.credential;

import org.apache.commons.codec.digest.Crypt;
import org.springframework.stereotype.Component;

@Component
public class CryptSaltFactory {
  private static final String NON_EXISTENT_PASSWORD = "";

  public String generateSalt() {
    return generateSalt(NON_EXISTENT_PASSWORD);
  }

  public String generateSalt(String password) {
    // Password hash format comes from crypt(3) using SHA-512,
    // which is $6$<salt>$<hashed_word>
    // We need to save the salt portion so that the hash can be
    // consistently generated across requests.
    final String passwordHash = Crypt.crypt(password);
    return passwordHash.substring(0, passwordHash.lastIndexOf("$"));
  }
}
