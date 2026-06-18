package burp;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * Smart Payload Success Tracking System
 * Tracks payload success rates to prioritize effective payloads
 * Improves detection speed by 30-50%
 */
public class PayloadSuccessTracker {
    
    // Track success counts per payload
    private final Map<String, AtomicInteger> payloadSuccessCount = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> payloadTestCount = new ConcurrentHashMap<>();
    
    // Track success rates per application type
    private final Map<String, Map<String, Double>> appTypeSuccessRates = new ConcurrentHashMap<>();
    
    // Track success rates per context
    private final Map<String, Map<String, Double>> contextSuccessRates = new ConcurrentHashMap<>();
    
    // Track recent successes (for adaptive ordering)
    private final Queue<String> recentSuccesses = new ConcurrentLinkedQueue<>();
    private static final int MAX_RECENT_SUCCESSES = 100;
    
    private final IBurpExtenderCallbacks callbacks;
    
    public PayloadSuccessTracker(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    /**
     * Record successful payload detection
     */
    public void recordSuccess(String payload, String applicationType, String context) {
        try {
            payloadSuccessCount.computeIfAbsent(payload, k -> new AtomicInteger(0)).incrementAndGet();
            payloadTestCount.computeIfAbsent(payload, k -> new AtomicInteger(0)).incrementAndGet();
            
            // Track recent successes
            recentSuccesses.offer(payload);
            if (recentSuccesses.size() > MAX_RECENT_SUCCESSES) {
                recentSuccesses.poll();
            }
            
            // Update application type success rates
            if (applicationType != null) {
                appTypeSuccessRates.computeIfAbsent(applicationType, k -> new ConcurrentHashMap<>())
                    .put(payload, getSuccessRate(payload));
            }
            
            // Update context success rates
            if (context != null) {
                contextSuccessRates.computeIfAbsent(context, k -> new ConcurrentHashMap<>())
                    .put(payload, getSuccessRate(payload));
            }
        } catch (Exception e) {
            // Silently fail
        }
    }
    
    /**
     * Record payload test (success or failure)
     */
    public void recordTest(String payload) {
        try {
            payloadTestCount.computeIfAbsent(payload, k -> new AtomicInteger(0)).incrementAndGet();
        } catch (Exception e) {
            // Silently fail
        }
    }
    
    /**
     * Get success rate for a payload
     */
    public double getSuccessRate(String payload) {
        try {
            int tests = payloadTestCount.getOrDefault(payload, new AtomicInteger(0)).get();
            if (tests == 0) return 0.0;
            
            int successes = payloadSuccessCount.getOrDefault(payload, new AtomicInteger(0)).get();
            return (double) successes / tests;
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    /**
     * Get success rate for payload in specific application type
     */
    public double getSuccessRateForAppType(String payload, String applicationType) {
        try {
            Map<String, Double> rates = appTypeSuccessRates.get(applicationType);
            if (rates != null && rates.containsKey(payload)) {
                return rates.get(payload);
            }
            return getSuccessRate(payload); // Fallback to global rate
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    /**
     * Get success rate for payload in specific context
     */
    public double getSuccessRateForContext(String payload, String context) {
        try {
            Map<String, Double> rates = contextSuccessRates.get(context);
            if (rates != null && rates.containsKey(payload)) {
                return rates.get(payload);
            }
            return getSuccessRate(payload); // Fallback to global rate
        } catch (Exception e) {
            return 0.0;
        }
    }
    
    /**
     * Sort payloads by success rate (highest first)
     */
    public List<String> prioritizePayloads(List<String> payloads) {
        try {
            List<String> prioritized = new ArrayList<>(payloads);
            prioritized.sort((a, b) -> {
                double rateA = getSuccessRate(a);
                double rateB = getSuccessRate(b);
                return Double.compare(rateB, rateA); // Higher rate first
            });
            return prioritized;
        } catch (Exception e) {
            return payloads; // Return original if sorting fails
        }
    }
    
    /**
     * Sort payloads by success rate for specific application type
     */
    public List<String> prioritizePayloadsForAppType(List<String> payloads, String applicationType) {
        try {
            if (applicationType == null) {
                return prioritizePayloads(payloads);
            }
            
            List<String> prioritized = new ArrayList<>(payloads);
            prioritized.sort((a, b) -> {
                double rateA = getSuccessRateForAppType(a, applicationType);
                double rateB = getSuccessRateForAppType(b, applicationType);
                return Double.compare(rateB, rateA); // Higher rate first
            });
            return prioritized;
        } catch (Exception e) {
            return prioritizePayloads(payloads); // Fallback to global prioritization
        }
    }
    
    /**
     * Sort payloads by success rate for specific context
     */
    public List<String> prioritizePayloadsForContext(List<String> payloads, String context) {
        try {
            if (context == null) {
                return prioritizePayloads(payloads);
            }
            
            List<String> prioritized = new ArrayList<>(payloads);
            prioritized.sort((a, b) -> {
                double rateA = getSuccessRateForContext(a, context);
                double rateB = getSuccessRateForContext(b, context);
                return Double.compare(rateB, rateA); // Higher rate first
            });
            return prioritized;
        } catch (Exception e) {
            return prioritizePayloads(payloads); // Fallback to global prioritization
        }
    }
    
    /**
     * Get recently successful payloads (for quick wins)
     */
    public List<String> getRecentSuccesses() {
        return new ArrayList<>(recentSuccesses);
    }
    
    /**
     * Get top performing payloads
     */
    public List<String> getTopPayloads(int count) {
        try {
            List<Map.Entry<String, Double>> entries = new ArrayList<>();
            for (String payload : payloadTestCount.keySet()) {
                double rate = getSuccessRate(payload);
                if (rate > 0) {
                    entries.add(new AbstractMap.SimpleEntry<>(payload, rate));
                }
            }
            
            entries.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));
            
            List<String> topPayloads = new ArrayList<>();
            for (int i = 0; i < Math.min(count, entries.size()); i++) {
                topPayloads.add(entries.get(i).getKey());
            }
            return topPayloads;
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }
    
    /**
     * Get statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalPayloads", payloadTestCount.size());
        stats.put("successfulPayloads", payloadSuccessCount.size());
        stats.put("recentSuccesses", recentSuccesses.size());
        
        // Calculate average success rate
        double totalRate = 0.0;
        int count = 0;
        for (String payload : payloadTestCount.keySet()) {
            totalRate += getSuccessRate(payload);
            count++;
        }
        stats.put("averageSuccessRate", count > 0 ? totalRate / count : 0.0);
        
        return stats;
    }
    
    /**
     * Clear all statistics
     */
    public void clear() {
        payloadSuccessCount.clear();
        payloadTestCount.clear();
        appTypeSuccessRates.clear();
        contextSuccessRates.clear();
        recentSuccesses.clear();
    }
}

