package com.example.springbootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //returns object
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .authorizeRequests().anyRequest().authenticated()
//                .and().formLogin().loginPage("/login").permitAll();
                .authorizeRequests().antMatchers("/","../css/**","../js/**","/register").access("hasAnyAuthority('USER', 'ADMIN')")
                .antMatchers("/admin").access("hasAuthority('ADMIN')")

                .and().formLogin().loginPage("/login").permitAll()
                .and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/login").permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.inMemoryAuthentication()
        .withUser("user")
        .password(passwordEncoder().encode("password")).authorities("USER")
        .and()
        .withUser("dave")
        .password(passwordEncoder().encode("begreat")).authorities("ADMIN");
    }





}
