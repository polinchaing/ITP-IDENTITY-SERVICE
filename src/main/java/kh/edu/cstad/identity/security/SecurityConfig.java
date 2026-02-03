package kh.edu.cstad.identity.security;


import kh.edu.cstad.identity.domain.User;
import kh.edu.cstad.identity.features.user.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static org.springframework.security.authorization.SingleResultAuthorizationManager.permitAll;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final PasswordEncoder passwordEncoder;
    //    private final UserDetailsService userDetailsService;
    private final UserRepository userRepository;

    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String issuerUri;


    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailServiceImpl userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setHideUserNotFoundExceptions(false);
        return provider;
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings
                .builder()
                .issuer(issuerUri)
                .build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain configureOAuth2(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())    // Initialize `OidcConfigurer`
                )


                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                );

        http
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );


        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/login/oauth2/**", "/resources/**", "/oauth2/login/**", "/public/**").permitAll()
                        .requestMatchers("/login", "/css/**", "/js/**", "/images/**", "/public/**").permitAll()
                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
                .formLogin(f -> f
                        .loginPage("/login")
                        .permitAll())
                .cors(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

//    @Bean
//    public Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper() {
//        return context -> {
//            OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
//            JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
//
//            String username = principal.getToken().getClaimAsString("sub");
//
//            User user = userRepository.findByUsername(username)
//                    .orElseThrow(() -> new ResponseStatusException(
//                            HttpStatus.NOT_FOUND, "User not found: " + username
//                    ));
//
//            Map<String, Object> claims = new HashMap<>();
//            claims.put("sub", username);
//            claims.put("preferred_username", user.getUsername());
//            claims.put("email", user.getEmail());
//            claims.put("family_name", user.getFamilyName());
//            claims.put("given_name", user.getGivenName());
//            claims.put("name", user.getGivenName() + " " + user.getFamilyName());
//            claims.put("phone_number", user.getPhoneNumber());
//            claims.put("gender", user.getGender());
//            claims.put("birthdate", user.getDob() != null ? user.getDob().toString() : null);
//

    /// /            claims.put("picture", user.getProfileImage());
    /// /            claims.put("cover_image", user.getCoverImage());
    /// /            claims.put("roles", user.getRoles().stream()
    /// /                    .map(role -> role.getName())
    /// /                    .toList());
//
//            return new OidcUserInfo(claims);
//        };
//    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(UserRepository userRepository) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) ||
                    "id_token".equals(context.getTokenType().getValue())) {
                Authentication principal = context.getPrincipal();

                if (principal.getPrincipal() instanceof UserDetails userDetails) {
                    User user = userRepository.findByUsername(userDetails.getUsername()).orElseThrow(
                            () -> new ResponseStatusException(HttpStatus.NOT_FOUND, "user not found")
                    );

                    context.getClaims().claim("preferred_username", user.getUsername());
                    context.getClaims().claim("email", user.getEmail());
                    context.getClaims().claim("gender", user.getGender());
                    context.getClaims().claim("family_name", user.getFamilyName());
                    context.getClaims().claim("given_name", user.getGivenName());
                    context.getClaims().claim("phone_number", user.getPhoneNumber());
                    context.getClaims().claim("birthdate", user.getDob() != null ? user.getDob().toString() : null);

                }
            }
        };
    }


}
