package io.pivotal.security.oauth;

public class RequestToOperationTranslator {
  private String path;
  private String method;

  public RequestToOperationTranslator(String path) {
    this.path = path;
  }

  public RequestToOperationTranslator setMethod(String method) {
    this.method = method;
    return this;
  }

  public String translate() {
    StringBuilder s = new StringBuilder();
    if(path.startsWith("/api/v1/data")) {
      s.append("credential");
    } else if(path.startsWith("/api/v1/ca")) {
      s.append("ca");
    }
    switch(method) {
      case "PUT":
      case "POST":
        s.append("_update");
        break;
      case "GET":
        s.append("_access");
        break;
      case "DELETE":
        s.append("_delete");
        break;
    }
    return s.toString();
  }
}
