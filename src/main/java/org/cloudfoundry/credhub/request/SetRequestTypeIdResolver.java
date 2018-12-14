package org.cloudfoundry.credhub.request;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.DatabindContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import com.fasterxml.jackson.databind.jsontype.TypeIdResolver;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.cloudfoundry.credhub.entity.SshCredentialVersionData;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;

public class SetRequestTypeIdResolver implements TypeIdResolver {
  private JavaType baseType;

  @Override
  public void init(final JavaType baseType) {
    this.baseType = baseType;
  }

  @Override
  public String idFromValue(final Object value) {
    return null;
  }

  @Override
  public String idFromValueAndType(final Object value, final Class<?> suggestedType) {
    return null;
  }

  @Override
  public String idFromBaseType() {
    return null;
  }

  @Override
  public JavaType typeFromId(final DatabindContext context, final String id) throws IOException {
    final Class<?> subType;
    final String lowerCaseId = id.toLowerCase();

    switch (lowerCaseId) {
      case CertificateCredentialVersionData.CREDENTIAL_TYPE:
        subType = CertificateSetRequest.class;
        break;
      case ValueCredentialVersionData.CREDENTIAL_TYPE:
        subType = ValueSetRequest.class;
        break;
      case JsonCredentialVersionData.CREDENTIAL_TYPE:
        subType = JsonSetRequest.class;
        break;
      case PasswordCredentialVersionData.CREDENTIAL_TYPE:
        subType = PasswordSetRequest.class;
        break;
      case RsaCredentialVersionData.CREDENTIAL_TYPE:
        subType = RsaSetRequest.class;
        break;
      case SshCredentialVersionData.CREDENTIAL_TYPE:
        subType = SshSetRequest.class;
        break;
      case UserCredentialVersionData.CREDENTIAL_TYPE:
        subType = UserSetRequest.class;
        break;
      default:
        final String message = String.format("Could not resolve type id '%s' into a subtype of %s", lowerCaseId, baseType);
        throw new InvalidTypeIdException(null, message, baseType, lowerCaseId);
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
