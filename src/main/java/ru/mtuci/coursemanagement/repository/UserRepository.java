package ru.mtuci.coursemanagement.repository;

import ru.mtuci.coursemanagement.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = :attempts WHERE u.id = :userId")
    void updateFailedAttempts(@Param("userId") Long userId, @Param("attempts") int attempts);
    
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.accountLocked = :locked, u.lockedUntil = :lockedUntil WHERE u.id = :userId")
    void lockAccount(@Param("userId") Long userId, @Param("locked") boolean locked, 
                     @Param("lockedUntil") LocalDateTime lockedUntil);
    
    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") Long userId, @Param("lastLogin") LocalDateTime lastLogin);
}