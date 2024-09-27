package com.example.correction_tps.service;


import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitService {

    // Buckets pour les opérations normales
    private final ConcurrentHashMap<String, Bucket> normalBuckets = new ConcurrentHashMap<>();

    // Buckets pour les opérations critiques
    private final ConcurrentHashMap<String, Bucket> criticalBuckets = new ConcurrentHashMap<>();

    // Limite pour les opérations normales : 10 requêtes toutes les 10 minutes
    private static final Bandwidth NORMAL_LIMIT = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(10)));

    // Limite pour les opérations critiques : 5 requêtes par heure
    private static final Bandwidth CRITICAL_LIMIT = Bandwidth.classic(5, Refill.greedy(5, Duration.ofHours(1)));

    // Vérification pour les transactions normales
    public boolean allowNormalTransaction(String userId) {
        Bucket bucket = normalBuckets.computeIfAbsent(userId, this::createNormalBucket);
        return bucket.tryConsume(1);
    }

    // Vérification pour les transactions critiques
    public boolean allowCriticalTransaction(String userId) {
        Bucket bucket = criticalBuckets.computeIfAbsent(userId, this::createCriticalBucket);
        return bucket.tryConsume(1);
    }

    // Créer un bucket pour les opérations normales
    private Bucket createNormalBucket(String userId) {
        return Bucket4j.builder().addLimit(NORMAL_LIMIT).build();
    }

    // Créer un bucket pour les opérations critiques
    private Bucket createCriticalBucket(String userId) {
        return Bucket4j.builder().addLimit(CRITICAL_LIMIT).build();
    }
}
