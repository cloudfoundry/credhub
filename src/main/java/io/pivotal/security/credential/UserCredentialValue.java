package io.pivotal.security.credential;

import static com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.digest.Crypt;
import org.hibernate.validator.constraints.NotEmpty;

public class UserCredentialValue implements CredentialValue {
  private String username;
  @NotEmpty(message = "error.missing_password")
  private String password;
  private String salt;

  public UserCredentialValue() {}

  public UserCredentialValue(String username, String password, String salt) {
    this.username = username;
    this.password = password;
    this.salt = salt;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @JsonIgnore
  public String getSalt() {
    if (salt == null) {
      salt = new CryptSaltFactory().generateSalt(password);
    }

    return salt;
  }

  @JsonProperty(value = "password_hash", access = READ_ONLY)
  @SuppressWarnings("unused")
  public String getPasswordHash() {
    return Crypt.crypt(getPassword(), getSalt());
  }
}
