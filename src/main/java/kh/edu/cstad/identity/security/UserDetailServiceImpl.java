package kh.edu.cstad.identity.security;


import kh.edu.cstad.identity.auditable.CustomUserDetails;
import kh.edu.cstad.identity.domain.User;
import kh.edu.cstad.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username).orElseThrow(
                () -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,"User not found"
                )
        );

        log.info("✅ User found: {}", user.getUsername());
        log.info("   Email: {}", user.getEmail());
        log.info("   Enabled: {}", user.getIsEnabled());
        log.info("   Account Non Expired: {}", user.getAccountNonExpired());
        log.info("   Account Non Locked: {}", user.getAccountNonLocked());
        log.info("   Credentials Non Expired: {}", user.getCredentialsNonExpired());
        log.info("   Roles: {}", user.getRoles() != null ? user.getRoles().size() : 0);
        log.info("   Permissions: {}", user.getPermissions() != null ? user.getPermissions().size() : 0);
        log.info("   Password present: {}", user.getPassword() != null && !user.getPassword().isEmpty());

        CustomUserDetails userDetails = new CustomUserDetails(user);

        log.info("✅ CustomUserDetails created");
        log.info("   Authorities: {}", userDetails.getAuthorities().size());
        userDetails.getAuthorities().forEach(auth ->
                log.info("      - {}", auth.getAuthority())
        );
        log.info("   Is Enabled: {}", userDetails.isEnabled());
        log.info("   Is Account Non Expired: {}", userDetails.isAccountNonExpired());
        log.info("   Is Account Non Locked: {}", userDetails.isAccountNonLocked());
        log.info("   Is Credentials Non Expired: {}", userDetails.isCredentialsNonExpired());

//        String[] roles = loggedInUser.getRoles().stream()
//                .map(Role::getName)
//                .toArray(String[]::new);

//        List<GrantedAuthority> authorities = new ArrayList<>();
//        loggedInUser.getRoles().forEach(role -> {
//            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
//            role.getPermissions().forEach(permission -> {
//                authorities.add(new SimpleGrantedAuthority(permission.getName()));
//            });
//        });

//        UserDetails userSecurity = org.springframework.security.core.userdetails.User.builder()
//                .username(loggedInUser.getUsername())
//                .password(loggedInUser.getPassword())
////                .roles(roles)
//                .authorities(authorities)
//                .build();

//        log.info("UserDetailsServiceImpl loadUserByUsername = {}", loggedInUser.getUsername());
//        log.info("UserDetailsServiceImpl loadUserRoles = {}" ,userSecurity.getAuthorities());
        return userDetails;
    }
}
