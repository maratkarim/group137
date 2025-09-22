package sec.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import sec.security.service.UserService;
import sec.security.service.impl.UserServiceImpl;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService; // внедряем готовый @Service
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Bean
    public PasswordEncoder passwordEncoder() { return passwordEncoder; }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        var amb = http.getSharedObject(AuthenticationManagerBuilder.class);
        amb.userDetailsService(userService).passwordEncoder(passwordEncoder);
        return amb.build();
    }

    // ===== REST chain (высокий приоритет) =====
    @Bean
    @Order(1)
    public SecurityFilterChain restChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/rest/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .exceptionHandling(e -> e
                        // если не вошёл → 401, без редиректов и HTML
                        .authenticationEntryPoint(new org.springframework.security.web.authentication.HttpStatusEntryPoint(org.springframework.http.HttpStatus.UNAUTHORIZED))
                )
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/rest/login", "/rest/registration").permitAll()
                        .requestMatchers("/rest/logout").authenticated()
                        .requestMatchers("/rest/setAdmin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated()
                )
                // для REST отключаем formLogin/httpBasic
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);
        return http.build();
    }

    // ===== WEB chain (ниже приоритет) =====
    @Bean
    @Order(2)
    public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .exceptionHandling(ex -> ex.accessDeniedPage("/forbidden"))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/css/**", "/js/**").permitAll()
                        .requestMatchers("/sign-in", "/entering", "/sign-up", "/registration").anonymous()
                        .requestMatchers("/sign-out", "/change-password", "/save-password").authenticated()
                        .requestMatchers("/profile").authenticated()
                        .requestMatchers("/admin-page").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/user-page").hasAuthority("ROLE_USER")
                        .anyRequest().permitAll()
                )
                .formLogin(login -> login
                        .loginProcessingUrl("/entering")
                        .defaultSuccessUrl("/profile")
                        .loginPage("/sign-in")              // верните страницу логина, чтобы не было дефолтного /login
                        .failureUrl("/sign-in?error")
                        .usernameParameter("user_email")
                        .passwordParameter("user_password")
                )
                .logout(l -> l.logoutUrl("/sign-out").logoutSuccessUrl("/sign-in?logout"))
                .httpBasic(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
