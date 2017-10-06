package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import io.pivotal.security.entity.CertificateCredentialVersion;
import io.pivotal.security.entity.JsonCredentialVersion;
import io.pivotal.security.entity.PasswordCredentialVersion;
import io.pivotal.security.entity.RsaCredentialVersion;
import io.pivotal.security.entity.SshCredentialVersion;
import io.pivotal.security.entity.UserCredentialVersion;
import io.pivotal.security.entity.ValueCredentialVersion;

import java.io.IOException;

public class SetRequestTypeIdResolver implements TypeIdResolver {
  private JavaType baseType;

  @Override
  public void init(JavaType baseType) {
    this.baseType = baseType;
  }

  @Override
  public String idFromValue(Object value) {
    return null;
  }

  @Override
  public String idFromValueAndType(Object value, Class<?> suggestedType) {
    return null;
  }

  @Override
  public String idFromBaseType() {
    return null;
  }

  @Override
  public JavaType typeFromId(DatabindContext context, String id) throws IOException {
    Class<?> subType;
    id = id.toLowerCase();

    switch (id) {
      case CertificateCredentialVersion.CREDENTIAL_TYPE:
        subType = CertificateSetRequest.class;
        break;
      case ValueCredentialVersion.CREDENTIAL_TYPE:
        subType = ValueSetRequest.class;
        break;
      case JsonCredentialVersion.CREDENTIAL_TYPE:
        subType = JsonSetRequest.class;
        break;
      case PasswordCredentialVersion.CREDENTIAL_TYPE:
        subType = PasswordSetRequest.class;
        break;
      case RsaCredentialVersion.CREDENTIAL_TYPE:
        subType = RsaSetRequest.class;
        break;
      case SshCredentialVersion.CREDENTIAL_TYPE:
        subType = SshSetRequest.class;
        break;
      case UserCredentialVersion.CREDENTIAL_TYPE:
        subType = UserSetRequest.class;
        break;
      default:
        String message = String.format("Could not resolve type id '%s' into a subtype of %s", id, baseType);
        throw new InvalidTypeIdException(null, message, baseType, id);
    }

    return context.constructSpecializedType(baseType, subType);
  }

  @Override
  public String getDescForKnownTypeIds() {
    return null;
  }

  @Override
  public JsonTypeInfo.Id getMechanism() {
    return JsonTypeInfo.Id.CUSTOM;
  }
}
