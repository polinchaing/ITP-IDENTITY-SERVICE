package kh.edu.cstad.identity.security;


import kh.edu.cstad.identity.domain.Role;
import kh.edu.cstad.identity.domain.User;
import kh.edu.cstad.identity.features.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Load or find user from database
        User loggedInUser = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        // Map Role to Array of String
//        String[] roles = loggedInUser.getRoles().stream()
//                .map(Role::getName)
//                .toArray(String[]::new);

        // Get only Role Authority
//        Set<GrantedAuthority> authorities = loggedInUser.getRoles()
//                .stream()
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
//                .collect(Collectors.toSet());


        // Get Both Of Role And Permission Authorities
        List<GrantedAuthority> authorities = new ArrayList();

        loggedInUser.getRoles().forEach(role->{
            // add role into authority
            authorities.add(new SimpleGrantedAuthority("ROLE_"+ role.getName()));
            role.getPermissions().forEach(permission->{
                // add permission into authority
                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            });
        });

        // Build UserDetails object
        UserDetails userSecurity = org.springframework.security.core.userdetails.User.builder()
                .username(loggedInUser.getUsername())
                .password(loggedInUser.getPassword())
                //.roles(roles)
                .authorities(authorities)
                .build();
        log.info("UserDetailsServiceImpl loadUserByUsername = {}", userSecurity.getAuthorities());
        log.info("UserDetailsServiceImpl loadUserByUsername = {}", userSecurity.getUsername());

        return userSecurity;
    }
}

