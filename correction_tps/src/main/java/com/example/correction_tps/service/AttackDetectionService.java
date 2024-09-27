package com.example.correction_tps.service;

import com.example.correction_tps.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;


@Service
public class AttackDetectionService {
    public boolean isSuspiciousLogin(User user, HttpServletRequest request) {
        String currentIp = request.getRemoteAddr();
        if (user.getLastKnownIp() != null && !user.getLastKnownIp().equals(currentIp)) {
            logSuspiciousActivity(user.getUsername(), currentIp);
            return true;
        }
        user.setLastKnownIp(currentIp);
        return false;
    }

    private void logSuspiciousActivity(String username, String currentIp) {
        System.out.println("Suspicious login for user: " + username + " from IP: " + currentIp);
    }
}