package CarpinteriaBack.Login.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new PasswordEncoder() {
	        @Override
	        public String encode(CharSequence rawPassword) {
	            return rawPassword.toString();
	        }

	        @Override
	        public boolean matches(CharSequence rawPassword, String encodedPassword) {
	            return rawPassword.toString().equals(encodedPassword);
	        }
	    };
	}
    @Bean
    public DaoAuthenticationProvider authProvider(UserDetailsService userDetailsService,
                                                  PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())

                // 🚫 QUITAR LOGIN AUTOMÁTICO DE SPRING
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(form -> form.disable())

                .authorizeHttpRequests(auth -> auth

                        // ✅ permitir preflight (CORS)
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 🔓 rutas públicas
                        .requestMatchers(
                                "/",
                                "/index.html",
                                "/assets/**",
                                "/api/auth/login",
                                "/producto/public/**"
                        ).permitAll()

                        // 🔐 rutas ADMIN
                        .requestMatchers(
                                "/api/dashboard/**",
                                "/api/admin/**",
                                "/api/productos/**",
                                "/api/empleados/**",
                                "/api/roles/**",
                                "/api/clientes/**",
                                "/categoria/api/**",
                                "/api/pedidos/**",
                                "/lineadiseno/api/**",
                                "/producto/api/**"
                        ).hasRole("ADMINISTRADOR")

                        // 🔓 TODO lo demás libre (IMPORTANTE)
                        .anyRequest().permitAll()
                )
                .build();
    }

    // ✅ CONFIG CORS PARA ANGULAR
    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
        var config = new org.springframework.web.cors.CorsConfiguration();

        config.setAllowedOrigins(java.util.List.of(
        		 "http://localhost:4200",
        	        "http://localhost:64348",
        	        "https://boyd123456.github.io",
        	        "https://boyd123456.github.io/backend-tienda"
        ));

        config.setAllowedMethods(java.util.List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        config.setAllowedHeaders(java.util.List.of("*"));
        config.setExposedHeaders(java.util.List.of("Authorization"));
        config.setAllowCredentials(true);

        var source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}