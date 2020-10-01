package com.example.jca;

import java.security.Security;

public class SecurityProviderDetails {

  public static void main(String[] args) {
    System.out.println(String.format("%s providers found", Security.getProviders().length));
    for (var p : Security.getProviders()) {
      System.out.println(
          String.format(
              " Provider: name=%s, version=%s, services=%s, info=%s",
              p.getName(), p.getVersionStr(), p.getServices().size(), p.getInfo()));
      for (var s : p.getServices()) {
        System.out.println(
            String.format("  Service: name=%s, type=%s", s.getAlgorithm(), s.getType()));
      }
    }
  }
}
