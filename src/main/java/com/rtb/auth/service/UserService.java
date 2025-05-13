package com.rtb.auth.service;

import com.rtb.auth.enums.RoleType;
import com.rtb.core.entity.user.Role;
import com.rtb.core.entity.user.User;
import com.rtb.core.repository.RoleRepository;
import com.rtb.core.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Optional;

@Slf4j
@Service
public class UserService {

  private final BCryptPasswordEncoder passwordEncoder;

  private final RoleRepository roleRepository;

  private final UserRepository userRepository;

  private final OtpService otpService;

  public UserService(RoleRepository roleRepository,
                     UserRepository userRepository, OtpService otpService) {
    this.otpService = otpService;
    this.passwordEncoder = new BCryptPasswordEncoder(12, new SecureRandom());
    this.roleRepository = roleRepository;
    this.userRepository = userRepository;
  }


  public Optional<User> getUserByEmailAndRole(String email, RoleType roleType) {
    Role role = roleRepository.findByRoleName(roleType.name()).get();

    return userRepository.findByEmailAndRole(email.toLowerCase(), role);
  }
  public Optional<User> getUserByEmail(String email) {

    return userRepository.findByEmail(email.toLowerCase());
  }

  public boolean verifyUserPassword(User user, String password) {
    return passwordEncoder.matches(password, user.getPassword());
  }

  public User saveUser(User user) {
    return userRepository.save(user);
  }
}