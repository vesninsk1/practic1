package ru.mtuci.coursemanagement.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.util.concurrent.TimeUnit;

@Component
public class RateLimiter {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;
    
    @Value("${app.security.rate-limit.max-attempts:5}")
    private int maxAttempts;
    
    @Value("${app.security.rate-limit.block-time-minutes:15}")
    private int blockTimeMinutes;
    
    public boolean isAllowed(String key) {
        String attemptsStr = redisTemplate.opsForValue().get(key);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;
        return attempts < maxAttempts;
    }
    
    public void recordAttempt(String key) {
        String attemptsStr = redisTemplate.opsForValue().get(key);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;
        attempts++;
        
        redisTemplate.opsForValue().set(
            key, 
            String.valueOf(attempts), 
            blockTimeMinutes, 
            TimeUnit.MINUTES
        );
    }
    
    public int getRemainingAttempts(String key) {
        String attemptsStr = redisTemplate.opsForValue().get(key);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;
        return Math.max(0, maxAttempts - attempts);
    }
    
    public void resetAttempts(String key) {
        redisTemplate.delete(key);
    }
    
    public boolean isBlocked(String key) {
        return !isAllowed(key);
    }
}