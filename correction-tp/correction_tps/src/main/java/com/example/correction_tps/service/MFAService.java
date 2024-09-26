package com.example.correction_tps.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class MFAService {

    private Map<String, String> otpCache = new ConcurrentHashMap<>();

    public String generateOTP(String username) {
        String otp = String.valueOf(100000 + new Random().nextInt(900000));  // Generate a 6-digit OTP
        otpCache.put(username, otp);
        System.out.println("OTP for " + username + " is: " + otp);  // Simulate sending OTP by printing it
        return otp;
    }

    public boolean validateOTP(String username, String inputOtp) {
        String generatedOtp = otpCache.get(username);
        return generatedOtp != null && generatedOtp.equals(inputOtp);
    }
}