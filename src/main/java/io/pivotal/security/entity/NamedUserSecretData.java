package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@DiscriminatorValue("user")
@SecondaryTable(
    name = NamedUserSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class NamedUserSecretData extends NamedSecretData<NamedUserSecretData> {
  public static final String TABLE_NAME = "UserSecret";
  public static final String SECRET_TYPE = "user";

  @Column(table = NamedUserSecretData.TABLE_NAME, length = 7000)
  private String username;

  public NamedUserSecretData() {
    this(null);
  }

  public NamedUserSecretData(String name) {
    super(name);
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  public String getUsername() {
    return username;
  }

  public NamedUserSecretData setUsername(String username) {
    this.username = username;
    return this;
  }
}
