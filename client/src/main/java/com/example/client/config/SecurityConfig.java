package com.example.client.config;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Configuration
public class SecurityConfig {
    static {
        // Initialize the Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());
    }
}
