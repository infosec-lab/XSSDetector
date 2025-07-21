package burp;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;

/**
 * XSSDetector Error Recovery System
 * Provides automated error recovery, circuit breaker pattern, retry mechanisms, and fallback strategies
 * 
 * @author Vikas Kumar
 * @version 2025.1.0
 */
public class ErrorRecoverySystem {
    
    private final IBurpExtenderCallbacks callbacks;
    private final PerformanceMonitor performanceMonitor;
    
    // Retry configuration
    private int maxRetryAttempts = 3;
    private long baseRetryDelay = 1000; // 1 second
    private double backoffMultiplier = 2.0;
    private long maxRetryDelay = 30000; // 30 seconds
    
    // Circuit breaker configuration
    private final Map<String, CircuitBreaker> circuitBreakers = new ConcurrentHashMap<>();
    private int circuitBreakerThreshold = 5; // failures before opening circuit
    private long circuitBreakerTimeout = 60000; // 1 minute
    private long circuitBreakerResetTimeout = 300000; // 5 minutes
    
    // Error tracking
    private final Map<String, AtomicInteger> errorCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> lastErrorTimes = new ConcurrentHashMap<>();
    private final Map<String, List<String>> errorHistory = new ConcurrentHashMap<>();
    
    // Recovery strategies
    private final Map<Class<? extends Throwable>, RecoveryStrategy> recoveryStrategies = new ConcurrentHashMap<>();
    
    // Thread pool for async recovery operations - OPTIMIZED
    private final ExecutorService recoveryExecutor = Executors.newFixedThreadPool(1); // REDUCED from 2 to 1
    
    // CRITICAL FIX: Thread count management to respect UI settings
    private static final int MAX_RECOVERY_THREADS = 1;
    private static final int MAX_ASYNC_OPERATIONS = 5; // Limit concurrent async operations
    
    public ErrorRecoverySystem(IBurpExtenderCallbacks callbacks, PerformanceMonitor performanceMonitor) {
        this.callbacks = callbacks;
        this.performanceMonitor = performanceMonitor;
        
        initializeRecoveryStrategies();
        logInfo("ErrorRecoverySystem initialized with automated recovery mechanisms");
    }
    
    /**
     * Initialize default recovery strategies for common exceptions
     */
    private void initializeRecoveryStrategies() {
        // Network timeout recovery
        addRecoveryStrategy(java.net.SocketTimeoutException.class, (operation, exception, attempt) -> {
            logWarning("Network timeout detected, implementing exponential backoff");
            try {
                long delay = Math.min(baseRetryDelay * (long)Math.pow(backoffMultiplier, attempt), maxRetryDelay);
                Thread.sleep(delay);
                return RecoveryAction.RETRY;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return RecoveryAction.FAIL;
            }
        });
        
        // Connection refused recovery
        addRecoveryStrategy(java.net.ConnectException.class, (operation, exception, attempt) -> {
            logWarning("Connection refused, attempting alternative approach");
            if (attempt >= 2) {
                return RecoveryAction.FALLBACK;
            }
            try {
                Thread.sleep(baseRetryDelay * attempt);
                return RecoveryAction.RETRY;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return RecoveryAction.FAIL;
            }
        });
        
        // Memory issues recovery - handle as RuntimeException
        addRecoveryStrategy(RuntimeException.class, (operation, exception, attempt) -> {
            if (exception.getCause() instanceof OutOfMemoryError || 
                exception.getMessage().contains("OutOfMemoryError") ||
                exception.getMessage().contains("memory")) {
                logError("Memory issue detected, triggering emergency cleanup");
                performEmergencyCleanup();
                if (attempt < 2) {
                    return RecoveryAction.RETRY;
                }
                return RecoveryAction.FALLBACK;
            }
            
            if (attempt >= maxRetryAttempts) {
                return RecoveryAction.FALLBACK;
            }
            try {
                Thread.sleep(baseRetryDelay);
                return RecoveryAction.RETRY;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return RecoveryAction.FAIL;
            }
        });
        
        // Generic exception recovery
        addRecoveryStrategy(Exception.class, (operation, exception, attempt) -> {
            if (attempt >= maxRetryAttempts) {
                return RecoveryAction.FALLBACK;
            }
            try {
                Thread.sleep(baseRetryDelay);
                return RecoveryAction.RETRY;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return RecoveryAction.FAIL;
            }
        });
    }
    
    /**
     * Execute an operation with automatic error recovery
     */
    public <T> T executeWithRecovery(String operationName, Supplier<T> operation) {
        return executeWithRecovery(operationName, operation, null);
    }
    
    /**
     * Execute an operation with automatic error recovery and fallback
     */
    public <T> T executeWithRecovery(String operationName, Supplier<T> operation, Supplier<T> fallback) {
        CircuitBreaker circuitBreaker = getOrCreateCircuitBreaker(operationName);
        
        // Check if circuit breaker is open
        if (circuitBreaker.isOpen()) {
            logWarning("Circuit breaker is open for operation: " + operationName + ", using fallback");
            return executeFallback(fallback, operationName);
        }
        
        int attempt = 0;
        Exception lastException = null;
        
        while (attempt < maxRetryAttempts) {
            try {
                attempt++;
                long startTime = performanceMonitor.startOperation(operationName);
                
                T result = operation.get();
                
                performanceMonitor.endOperation(operationName, startTime, true);
                circuitBreaker.recordSuccess();
                
                if (attempt > 1) {
                    logInfo("Operation recovered successfully after " + (attempt - 1) + " retries: " + operationName);
                }
                
                return result;
                
            } catch (Exception e) {
                lastException = e;
                recordError(operationName, e);
                circuitBreaker.recordFailure();
                
                // Get recovery strategy for this exception type
                RecoveryStrategy strategy = getRecoveryStrategy(e.getClass());
                RecoveryAction action = strategy.handle(operationName, e, attempt);
                
                switch (action) {
                    case RETRY:
                        logInfo("Retrying operation: " + operationName + " (attempt " + attempt + "/" + maxRetryAttempts + ")");
                        continue;
                        
                    case FALLBACK:
                        logWarning("Using fallback for operation: " + operationName + " after " + attempt + " attempts");
                        return executeFallback(fallback, operationName);
                        
                    case FAIL:
                        logError("Operation failed permanently: " + operationName);
                        throw new RuntimeException("Operation failed after " + attempt + " attempts", lastException);
                }
            }
        }
        
        // All retries exhausted
        logError("All retry attempts exhausted for operation: " + operationName);
        return executeFallback(fallback, operationName);
    }
    
    /**
     * Execute an async operation with recovery
     */
    public <T> CompletableFuture<T> executeAsyncWithRecovery(String operationName, Supplier<T> operation) {
        return executeAsyncWithRecovery(operationName, operation, null);
    }
    
    /**
     * Execute an async operation with recovery and fallback
     */
    public <T> CompletableFuture<T> executeAsyncWithRecovery(String operationName, Supplier<T> operation, Supplier<T> fallback) {
        return CompletableFuture.supplyAsync(() -> executeWithRecovery(operationName, operation, fallback), recoveryExecutor);
    }
    
    /**
     * Execute fallback strategy
     */
    private <T> T executeFallback(Supplier<T> fallback, String operationName) {
        if (fallback != null) {
            try {
                long startTime = performanceMonitor.startOperation(operationName + "_fallback");
                T result = fallback.get();
                performanceMonitor.endOperation(operationName + "_fallback", startTime, true);
                return result;
            } catch (Exception e) {
                logError("Fallback also failed for operation: " + operationName, e);
                performanceMonitor.endOperation(operationName + "_fallback", 0, false);
            }
        }
        return null;
    }
    
    /**
     * Get or create circuit breaker for operation
     */
    private CircuitBreaker getOrCreateCircuitBreaker(String operationName) {
        return circuitBreakers.computeIfAbsent(operationName, k -> new CircuitBreaker(
            circuitBreakerThreshold, circuitBreakerTimeout, circuitBreakerResetTimeout));
    }
    
    /**
     * Get recovery strategy for exception type
     */
    private RecoveryStrategy getRecoveryStrategy(Class<? extends Throwable> exceptionType) {
        // Find exact match first
        RecoveryStrategy strategy = recoveryStrategies.get(exceptionType);
        if (strategy != null) {
            return strategy;
        }
        
        // Find compatible strategy by walking up the class hierarchy
        for (Map.Entry<Class<? extends Throwable>, RecoveryStrategy> entry : recoveryStrategies.entrySet()) {
            if (entry.getKey().isAssignableFrom(exceptionType)) {
                return entry.getValue();
            }
        }
        
        // Return default strategy
        return recoveryStrategies.get(Exception.class);
    }
    
    /**
     * Record error occurrence
     */
    private void recordError(String operationName, Exception e) {
        errorCounts.computeIfAbsent(operationName, k -> new AtomicInteger(0)).incrementAndGet();
        lastErrorTimes.put(operationName, System.currentTimeMillis());
        
        List<String> history = errorHistory.computeIfAbsent(operationName, k -> new ArrayList<>());
        synchronized (history) {
            history.add(new Date() + ": " + e.getClass().getSimpleName() + " - " + e.getMessage());
            // Keep only last 10 errors
            if (history.size() > 10) {
                history.remove(0);
            }
        }
    }
    
    /**
     * Perform emergency cleanup to recover from memory issues
     */
    private void performEmergencyCleanup() {
        logInfo("Performing emergency cleanup...");
        
        try {
            // Force garbage collection
            System.gc();
            Thread.sleep(100);
            System.gc();
            
            // Clear error history to free memory
            for (List<String> history : errorHistory.values()) {
                synchronized (history) {
                    history.clear();
                }
            }
            
            logInfo("Emergency cleanup completed");
            
        } catch (Exception e) {
            logError("Emergency cleanup failed", e);
        }
    }
    
    /**
     * Add custom recovery strategy
     */
    public void addRecoveryStrategy(Class<? extends Throwable> exceptionType, RecoveryStrategy strategy) {
        recoveryStrategies.put(exceptionType, strategy);
        logInfo("Added recovery strategy for: " + exceptionType.getSimpleName());
    }
    
    /**
     * Get error statistics
     */
    public String getErrorStatistics() {
        StringBuilder stats = new StringBuilder();
        stats.append("Error Recovery Statistics\n");
        stats.append("Generated: ").append(new Date()).append("\n\n");
        
        if (errorCounts.isEmpty()) {
            stats.append("No errors recorded.\n");
            return stats.toString();
        }
        
        stats.append("Error Counts by Operation\n");
        for (Map.Entry<String, AtomicInteger> entry : errorCounts.entrySet()) {
            String operation = entry.getKey();
            int count = entry.getValue().get();
            Long lastError = lastErrorTimes.get(operation);
            
            stats.append(operation).append(": ").append(count).append(" errors");
            if (lastError != null) {
                stats.append(" (last: ").append(new Date(lastError)).append(")");
            }
            stats.append("\n");
        }
        
        stats.append("\nCircuit Breaker Status\n");
        for (Map.Entry<String, CircuitBreaker> entry : circuitBreakers.entrySet()) {
            CircuitBreaker cb = entry.getValue();
            stats.append(entry.getKey()).append(": ").append(cb.getState())
                 .append(" (failures: ").append(cb.getFailureCount()).append(")\n");
        }
        
        return stats.toString();
    }
    
    /**
     * Reset error statistics
     */
    public void resetErrorStatistics() {
        errorCounts.clear();
        lastErrorTimes.clear();
        errorHistory.clear();
        circuitBreakers.clear();
        logInfo("Error statistics reset");
    }
    
    /**
     * Configure retry parameters
     */
    public void configureRetry(int maxAttempts, long baseDelay, double backoffMultiplier, long maxDelay) {
        this.maxRetryAttempts = maxAttempts;
        this.baseRetryDelay = baseDelay;
        this.backoffMultiplier = backoffMultiplier;
        this.maxRetryDelay = maxDelay;
        
        logInfo(String.format("Retry configuration updated: maxAttempts=%d, baseDelay=%dms, backoff=%.1f, maxDelay=%dms",
                maxAttempts, baseDelay, backoffMultiplier, maxDelay));
    }
    
    /**
     * Configure circuit breaker parameters
     */
    public void configureCircuitBreaker(int threshold, long timeout, long resetTimeout) {
        this.circuitBreakerThreshold = threshold;
        this.circuitBreakerTimeout = timeout;
        this.circuitBreakerResetTimeout = resetTimeout;
        
        logInfo(String.format("Circuit breaker configuration updated: threshold=%d, timeout=%dms, resetTimeout=%dms",
                threshold, timeout, resetTimeout));
    }
    
    /**
     * Shutdown recovery system
     */
    public void shutdown() {
        recoveryExecutor.shutdown();
        try {
            if (!recoveryExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                recoveryExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            recoveryExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logInfo("ErrorRecoverySystem shutdown completed");
    }
    
    // Utility methods
    private void logInfo(String message) {
        if (callbacks != null) {
            callbacks.printOutput("[ERROR RECOVERY] " + message);
        }
    }
    
    private void logWarning(String message) {
        if (callbacks != null) {
            callbacks.printError("[ERROR RECOVERY WARNING] " + message);
        }
    }
    
    private void logError(String message) {
        if (callbacks != null) {
            callbacks.printError("[ERROR RECOVERY ERROR] " + message);
        }
    }
    
    private void logError(String message, Exception e) {
        if (callbacks != null) {
            callbacks.printError("[ERROR RECOVERY ERROR] " + message + ": " + e.getMessage());
        }
    }
    
    /**
     * Recovery strategy interface
     */
    @FunctionalInterface
    public interface RecoveryStrategy {
        RecoveryAction handle(String operationName, Exception exception, int attemptNumber);
    }
    
    /**
     * Recovery action enum
     */
    public enum RecoveryAction {
        RETRY,    // Retry the operation
        FALLBACK, // Use fallback strategy
        FAIL      // Fail permanently
    }
    
    /**
     * Circuit breaker implementation
     */
    private static class CircuitBreaker {
        private final int failureThreshold;
        private final long timeout;
        private final long resetTimeout;
        
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicLong lastFailureTime = new AtomicLong(0);
        private final AtomicReference<CircuitState> state = new AtomicReference<>(CircuitState.CLOSED);
        
        enum CircuitState {
            CLOSED,     // Normal operation
            OPEN,       // Circuit is open, calls fail fast
            HALF_OPEN   // Testing if service has recovered
        }
        
        public CircuitBreaker(int failureThreshold, long timeout, long resetTimeout) {
            this.failureThreshold = failureThreshold;
            this.timeout = timeout;
            this.resetTimeout = resetTimeout;
        }
        
        public boolean isOpen() {
            CircuitState currentState = state.get();
            
            if (currentState == CircuitState.OPEN) {
                // Check if we should transition to half-open
                if (System.currentTimeMillis() - lastFailureTime.get() > resetTimeout) {
                    state.compareAndSet(CircuitState.OPEN, CircuitState.HALF_OPEN);
                    return false;
                }
                return true;
            }
            
            return false;
        }
        
        public void recordSuccess() {
            failureCount.set(0);
            state.set(CircuitState.CLOSED);
        }
        
        public void recordFailure() {
            lastFailureTime.set(System.currentTimeMillis());
            int failures = failureCount.incrementAndGet();
            
            if (failures >= failureThreshold) {
                state.set(CircuitState.OPEN);
            }
        }
        
        public CircuitState getState() {
            return state.get();
        }
        
        public int getFailureCount() {
            return failureCount.get();
        }
    }
} 