package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.view.ResponseError;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.error.DefaultOAuth2ExceptionRenderer;
import org.springframework.security.oauth2.provider.error.OAuth2ExceptionRenderer;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class OAuthExceptionRenderer extends DefaultOAuth2ExceptionRenderer implements OAuth2ExceptionRenderer {
  public OAuthExceptionRenderer() {
    setMessageConverters(getMessageConverters());
  }

  private List<HttpMessageConverter<?>> getMessageConverters() {
    List<HttpMessageConverter<?>> result = new ArrayList<>();
    result.add(new ResponseErrorMessageConverter());
    return result;
  }

  public class ResponseErrorMessageConverter extends MappingJackson2HttpMessageConverter {

    @Override
    protected void writeInternal(Object object, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
      super.writeInternal(transformObject(object), outputMessage);
    }

    protected Object transformObject(Object object) {
      final OAuth2Exception exception = (OAuth2Exception) object;
      return new ResponseError(exception.getLocalizedMessage());
    }
  }
}
