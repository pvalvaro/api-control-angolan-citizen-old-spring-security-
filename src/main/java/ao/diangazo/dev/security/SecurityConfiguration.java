package ao.diangazo.dev.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // {noop} => No operation for password encoder	(no password encoding needed)
        // if we need encode password, use passwordEncoder

        //BCryptPasswordEncoder encoder = passwordEncoder();
        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder()).withUser("dev")
                .password(passwordEncoder().encode("1234")).authorities("ADMIN");

        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder()).withUser("citizen")
                .password(passwordEncoder().encode("123")).authorities("CITIZEN");

        auth.inMemoryAuthentication().passwordEncoder(passwordEncoder()).withUser("manager")
                .password(passwordEncoder().encode("123")).authorities("MANAGER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //declares which Page(URL) will have What access type
        http
                .headers()
                .and()
                .authorizeRequests()
                .antMatchers("/api/citizen/").permitAll()
                .antMatchers("/api/citizen/save").hasAnyAuthority("ADMIN", "MANAGER")
                .antMatchers("/api/citizen/delete/**").hasAuthority("ADMIN")
                .antMatchers("/api/citizen//getAll").permitAll()
                .antMatchers("/api/citizen//get/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and().csrf().disable().httpBasic()
        ;
    }
}