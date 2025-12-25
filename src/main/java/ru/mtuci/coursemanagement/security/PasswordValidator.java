package ru.mtuci.coursemanagement.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {
    
    @Value("${app.security.password.min-length:12}")
    private int minLength;
    
    @Value("${app.security.password.require-uppercase:true}")
    private boolean requireUppercase;
    
    @Value("${app.security.password.require-lowercase:true}")
    private boolean requireLowercase;
    
    @Value("${app.security.password.require-digit:true}")
    private boolean requireDigit;
    
    @Value("${app.security.password.require-special:true}")
    private boolean requireSpecial;

    
    public void validate(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        
        if (password.length() < minLength) {
            throw new IllegalArgumentException(
                String.format("Password must be at least %d characters long", minLength)
            );
        }
        
        if (requireUppercase && !Pattern.compile("[A-Z]").matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }
        
        if (requireLowercase && !Pattern.compile("[a-z]").matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }
        
        if (requireDigit && !Pattern.compile("[0-9]").matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }

        if (requireSpecial && !Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]").matcher(password).find()) {
            throw new IllegalArgumentException("Password must contain at least one special character");
        }
    }
}