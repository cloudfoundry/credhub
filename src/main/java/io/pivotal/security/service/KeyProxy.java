package io.pivotal.security.service;

import java.security.Key;

class KeyProxy {
  private Key key;

  public KeyProxy(Key key) {
    this.key = key;
  }

  public Key getKey() {
    return key;
  }
}
