package com.rtb.auth;

import com.rtb.auth.config.AuthSigningKey;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@EnableCaching
@EnableScheduling
@SpringBootApplication
@EnableConfigurationProperties(AuthSigningKey.class)
@EnableMethodSecurity(prePostEnabled = true) // Enables @PreAuthorize
@EntityScan(basePackages = "com.rtb.core.entity")
@ComponentScan(basePackages = "com.rtb.core")
@EnableJpaRepositories(basePackages = "com.rtb.core.repository")
public class Application {

  protected Application() {

  }

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

}
