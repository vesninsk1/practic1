package ru.mtuci.coursemanagement.controller;

import ru.mtuci.coursemanagement.model.User;
import ru.mtuci.coursemanagement.repository.UserRepository;
import ru.mtuci.coursemanagement.security.PasswordValidator;
import ru.mtuci.coursemanagement.security.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Validated
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private PasswordValidator passwordValidator;
    
    @Autowired
    private RateLimiter rateLimiter;
    
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestParam @NotBlank String username,
            @Valid @RequestParam @NotBlank String email,
            @Valid @RequestParam @NotBlank String password,
            HttpServletRequest request) {
        
        String ipAddress = getClientIp(request);
        String rateLimitKey = "register:" + ipAddress;
        
        if (rateLimiter.isBlocked(rateLimitKey)) {
            auditLogger.warn("Registration rate limit exceeded for IP: {}", ipAddress);
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, 
                "Too many registration attempts. Please try again later.");
        }
        
        if (userRepository.existsByUsername(username)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username already exists");
        }
        
        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
        }
        
        try {
            passwordValidator.validate(password);
            String encodedPassword = passwordEncoder.encode(password);
            User user = new User(null, username, encodedPassword, email, "STUDENT");
            userRepository.save(user);
            
            auditLogger.info("User registered: {}, IP: {}", username, ipAddress);
            logger.debug("New user registered with username: {}", username);
            rateLimiter.resetAttempts(rateLimitKey);
            
            return ResponseEntity.ok(Map.of(
                "message", "User registered successfully",
                "username", username
            ));
            
        } catch (IllegalArgumentException e) {
            rateLimiter.recordAttempt(rateLimitKey);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            rateLimiter.recordAttempt(rateLimitKey);
            logger.error("Registration error for username: {}", username, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, 
                "Registration failed. Please try again.");
        }
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestParam @NotBlank String username,
            @Valid @RequestParam @NotBlank String password,
            HttpServletRequest request,
            HttpSession session) {
        
        String ipAddress = getClientIp(request);
        String sessionId = session.getId();
        String rateLimitKey = "login:" + username + ":" + ipAddress;
        auditLogger.info("Login attempt - User: {}, IP: {}, Session: {}",
            username, ipAddress, sessionId.substring(0, 8) + "...");
        if (rateLimiter.isBlocked(rateLimitKey)) {
            auditLogger.warn("Account locked for username: {}, IP: {}", username, ipAddress);
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                "Account is temporarily locked due to too many failed attempts.");
        }
        
        try {
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    rateLimiter.recordAttempt(rateLimitKey);
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, 
                        "Invalid credentials. Attempts left: " + 
                        rateLimiter.getRemainingAttempts(rateLimitKey));
                });
            if (Boolean.TRUE.equals(user.getAccountLocked())) {
                if (user.getLockedUntil() != null && 
                    user.getLockedUntil().isAfter(LocalDateTime.now())) {
                    throw new ResponseStatusException(HttpStatus.LOCKED,
                        "Account is locked until " + user.getLockedUntil());
                } else {
                    user.setAccountLocked(false);
                    user.setLockedUntil(null);
                    user.setFailedAttempts(0);
                    userRepository.save(user);
                }
            }
            
            if (!passwordEncoder.matches(password, user.getPassword())) {
                user.setFailedAttempts(user.getFailedAttempts() + 1);
                
                if (user.getFailedAttempts() >= 5) {
                    user.setAccountLocked(true);
                    user.setLockedUntil(LocalDateTime.now().plusMinutes(15));
                    auditLogger.warn("Account locked due to multiple failed attempts: {}", username);
                }
                
                userRepository.save(user);
                rateLimiter.recordAttempt(rateLimitKey);
                
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Invalid credentials. Attempts left: " + 
                    rateLimiter.getRemainingAttempts(rateLimitKey));
            }
            
            user.setFailedAttempts(0);
            user.setAccountLocked(false);
            user.setLockedUntil(null);
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
            
            rateLimiter.resetAttempts(rateLimitKey);
            
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());
            session.setAttribute("role", user.getRole());
            session.setAttribute("loginTime", LocalDateTime.now());
            auditLogger.info("Login successful - User: {}, Role: {}, IP: {}, Session: {}",
                user.getUsername(), user.getRole(), ipAddress, 
                sessionId.substring(0, 8) + "...");
            
            logger.debug("User {} logged in successfully", user.getUsername());
            
            return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "username", user.getUsername(),
                "role", user.getRole(),
                "sessionId", sessionId.substring(0, 8) + "..."
            ));
            
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Login error for username: {}", username, e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                "Login failed. Please try again.");
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        String username = (String) session.getAttribute("username");
        
        if (username != null) {
            auditLogger.info("User logged out: {}", username);
            logger.debug("User {} logged out", username);
        }
        
        session.invalidate();
        
        return ResponseEntity.ok(Map.of(
            "message", "Logout successful"
        ));
    }
    
    @GetMapping("/session-info")
    public ResponseEntity<?> getSessionInfo(HttpSession session) {
        Map<String, Object> sessionInfo = new HashMap<>();
        
        sessionInfo.put("sessionId", session.getId().substring(0, 8) + "...");
        sessionInfo.put("creationTime", session.getCreationTime());
        sessionInfo.put("lastAccessedTime", session.getLastAccessedTime());
        sessionInfo.put("maxInactiveInterval", session.getMaxInactiveInterval());
        if (session.getAttribute("username") != null) {
            sessionInfo.put("username", session.getAttribute("username"));
            sessionInfo.put("role", session.getAttribute("role"));
        }
        
        return ResponseEntity.ok(sessionInfo);
    }
    
    @GetMapping("/csrf-token")
    public ResponseEntity<?> getCsrfToken(HttpServletRequest request) {
        return ResponseEntity.ok(Map.of(
            "message", "CSRF protection is enabled"
        ));
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}