package com.example.jca;

import java.security.Security;

public class SecurityProviderSummary {

  public static void main(String[] args) {
    System.out.println(String.format("%s providers found", Security.getProviders().length));
    for (var p : Security.getProviders()) {
      System.out.println(
          String.format(
              " Provider: name=%s, version=%s, services=%s, info=%s",
              p.getName(), p.getVersionStr(), p.getServices().size(), p.getInfo()));
    }
  }
}
