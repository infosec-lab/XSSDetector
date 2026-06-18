# XSSDetector - Complete Source & Advanced Logic Mapping

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Component Hierarchy](#component-hierarchy)
3. [Detection Flow Diagrams](#detection-flow-diagrams)
4. [Advanced Logic Flows](#advanced-logic-flows)
5. [Data Structures & Models](#data-structures--models)
6. [Integration Points](#integration-points)
7. [Payload Management System](#payload-management-system)
8. [Issue Reporting Pipeline](#issue-reporting-pipeline)

---

## Architecture Overview

### Core Architecture Pattern
XSSDetector follows a **multi-engine detection architecture** with centralized orchestration:

```
┌─────────────────────────────────────────────────────────────┐
│                    BurpExtender (Main Entry)                  │
│  - Plugin Registration & Lifecycle Management                │
│  - UI Management & Settings Integration                     │
│  - Scan Orchestration                                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ├──────────────────────────────────┐
                            │                                  │
        ┌───────────────────▼───────────────────┐  ┌───────────▼──────────────┐
        │   Passive Scan Pipeline               │  │  Active Scan Pipeline    │
        │   - CheckReflection (Foundation)      │  │  - EnhancedAggressive    │
        │   - DOM XSS Detection                 │  │  - EngineIntegrationMgr  │
        │   - Client-Side Attack Detection      │  │  - Payload Injection     │
        │   - Architecture Analysis             │  │  - Exploit Validation    │
        └───────────────────┬───────────────────┘  └───────────┬──────────────┘
                            │                                  │
                            └──────────┬───────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │   EngineIntegrationManager          │
                    │   - Orchestrates All Engines        │
                    │   - Coordinates Detection           │
                    │   - Manages Evidence Collection     │
                    └──────────────────┬──────────────────┘
                                       │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
┌───────▼────────┐  ┌────────────────▼──────────────┐  ┌──────────▼──────────┐
│ PayloadManager │  │  AdvancedFilteringEngine       │  │ EnhancedIssueReporter│
│ - Payload Gen  │  │  - False Positive Reduction   │  │ - Issue Creation     │
│ - Context Aware│  │  - Validation Logic          │  │ - Burp Integration   │
│ - Prioritization│  │  - Exploit Verification      │  │ - Advisory Generation │
└────────────────┘  └───────────────────────────────┘  └──────────────────────┘
```

---

## Component Hierarchy

### 1. Core Entry Point: `BurpExtender.java`

**Responsibilities:**
- Burp Suite extension lifecycle management
- UI initialization and event handling
- Settings persistence
- Scan orchestration (passive & active)
- Issue consolidation

**Key Methods:**
```java
registerExtenderCallbacks()     // Initialization
doPassiveScan()                 // Passive detection entry
doActiveScan()                  // Active detection entry
performComprehensiveXSSDetection() // Multi-engine passive scan
performActiveXSSDetection()     // Multi-engine active scan
```

**Initialization Order (CRITICAL):**
1. `PerformanceMonitor` - Performance tracking
2. `ErrorRecoverySystem` - Error handling
3. `EnhancedIssueReporter` - Issue creation
4. `CheckReflection` - Core reflection detection
5. `ModernArchitectureDetector` - Architecture analysis
6. `AdvancedJSONAnalyzer` - JSON analysis
7. `AIContextAnalyzer` - AI-powered context analysis
8. `EngineIntegrationManager` - Engine orchestration
9. Enhanced engines (DOM XSS, Client-Side, Aggressive, Filtering)

### 2. Detection Engines

#### 2.1 `CheckReflection.java` - Foundation Engine
**Purpose:** Core reflection detection (matches Burp Reflector plugin behavior)

**Flow:**
```
doPassiveScan()
  └─> checkResponse()
      └─> extractParameters() [ModernParameterExtractor]
      └─> checkReflection() [for each parameter]
          └─> testReflection() [with test payloads]
          └─> EnhancedAggressive.doActiveScan() [if reflection found]
              └─> validateExploit() [confirm vulnerability]
              └─> createIssue() [if confirmed]
```

**Key Components:**
- `ModernParameterExtractor` - Extracts parameters from modern architectures
- `PayloadManager` - Provides context-aware payloads
- `AdvancedFilteringEngine` - Filters false positives
- `SessionHandlingManager` - Manages sessions/CSRF tokens

#### 2.2 `EnhancedAggressive.java` - Active Detection Engine
**Purpose:** Advanced active scanning with exploit validation

**Flow:**
```
doActiveScan(insertionPoint)
  └─> getResponseContentType() [content type filtering]
  └─> analyzeArchitecture() [ModernArchitectureDetector]
  └─> getContextAwarePayloads() [PayloadManager]
  └─> for each payload:
      └─> makeRequest() [with payload injection]
      └─> analyzeResponse() [check reflection & execution]
      └─> validateExploit() [confirm XSS execution]
      └─> createIssue() [if confirmed]
```

**Advanced Features:**
- Response caching (`ResponseCache`)
- Payload success tracking (`PayloadSuccessTracker`)
- Parameter reflection tracking (`ParameterReflectionTracker`)
- Real-time dynamic payload generation

#### 2.3 `EnhancedDOMXSSDetector.java` - DOM XSS Detection
**Purpose:** Client-side DOM-based XSS detection

**Flow:**
```
analyzeDOMXSS(requestResponse)
  └─> detectSources() [DOM_SOURCES patterns]
  └─> detectSinks() [DOM_SINKS patterns]
  └─> analyzeDataFlows() [source → sink correlation]
  └─> realTimeDynamicAnalysis() [WebSocket, ServiceWorker, etc.]
  └─> calculateVulnerabilityScore() [risk assessment]
  └─> generateExploitPOC() [proof of concept]
  └─> return DOMXSSResult
```

**Detection Patterns:**
- Source detection: `location.href`, `postMessage`, `URLSearchParams`, React Router params, Vue Router params, etc.
- Sink detection: `innerHTML`, `eval()`, `dangerouslySetInnerHTML`, `v-html`, etc.
- Framework-specific: React, Vue, Angular, Next.js, Nuxt, SvelteKit, etc.

#### 2.4 `EnhancedClientSideAttackDetector.java` - Client-Side Attacks
**Purpose:** Comprehensive client-side injection detection

**Flow:**
```
analyzeClientSideAttacks(requestResponse)
  └─> cspAnalysis() [CSP misconfiguration]
  └─> postMessageAnalysis() [postMessage vulnerabilities]
  └─> webSocketAnalysis() [WebSocket injection]
  └─> templateInjectionAnalysis() [client-side templates]
  └─> prototypePollutionAnalysis() [prototype pollution]
  └─> modernAPIAnalysis() [modern browser APIs]
  └─> webComponentsAnalysis() [Web Components]
  └─> calculateRiskScore() [aggregate risk]
  └─> return ClientSideAttackResult
```

#### 2.5 `ModernArchitectureDetector.java` - Architecture Analysis
**Purpose:** Detect application architecture and frameworks

**Detection:**
- SPA frameworks: React, Vue, Angular, Svelte, etc.
- API architectures: GraphQL, REST, JSON-RPC
- Modern patterns: JAMStack, Microservices, Serverless
- Framework versions and features

#### 2.6 `AdvancedFilteringEngine.java` - False Positive Reduction
**Purpose:** Validate vulnerabilities and filter false positives

**Validation Logic:**
```
isVulnerabilityTrulyExploitable(vulnerabilityData)
  └─> checkPayloadReflection() [payload in response?]
  └─> checkExecutionContext() [can payload execute?]
  └─> checkEncoding() [is encoding bypassed?]
  └─> checkWAFBypass() [WAF bypass confirmed?]
  └─> checkContextValidation() [context analysis valid?]
  └─> return true/false
```

---

## Detection Flow Diagrams

### Passive Scan Flow

```
HTTP Request/Response
        │
        ▼
┌───────────────────────┐
│  BurpExtender         │
│  doPassiveScan()      │
└───────────┬───────────┘
            │
            ├─> Scope Check
            │
            ▼
┌───────────────────────┐
│  CheckReflection      │
│  doPassiveScan()      │
└───────────┬───────────┘
            │
            ├─> Extract Parameters
            │   └─> ModernParameterExtractor
            │
            ├─> Check Reflection
            │   └─> Test Payloads
            │
            └─> If Reflection Found
                └─> EnhancedAggressive.doActiveScan()
                    └─> Validate Exploit
                    └─> Create Issue
            │
            ▼
┌───────────────────────┐
│  Comprehensive XSS    │
│  Detection            │
└───────────┬───────────┘
            │
            ├─> DOM XSS Detection (if enabled)
            │   └─> EnhancedDOMXSSDetector
            │
            ├─> Client-Side Attacks (if enabled)
            │   └─> EnhancedClientSideAttackDetector
            │
            ├─> Architecture Analysis (if enabled)
            │   └─> ModernArchitectureDetector
            │
            └─> JSON Analysis (if enabled)
                └─> AdvancedJSONAnalyzer
            │
            ▼
┌───────────────────────┐
│  Issue Consolidation │
│  consolidateDuplicateIssues() │
└───────────────────────┘
```

### Active Scan Flow

```
HTTP Request + Insertion Point
        │
        ▼
┌───────────────────────┐
│  BurpExtender         │
│  doActiveScan()       │
└───────────┬───────────┘
            │
            ├─> Scope Check
            │
            ▼
┌───────────────────────┐
│  performActiveXSS     │
│  Detection()          │
└───────────┬───────────┘
            │
            ├─> EnhancedAggressive (if aggressive mode)
            │   └─> Payload Injection
            │   └─> Exploit Validation
            │
            └─> EngineIntegrationManager (always)
                └─> Orchestrate All Engines
                └─> Coordinate Detection
            │
            ▼
┌───────────────────────┐
│  AdvancedFiltering    │
│  Engine               │
│  - Validate Exploits  │
│  - Filter False Pos   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  EnhancedIssueReporter│
│  createEnhancedXSSIssue│
└───────────────────────┘
```

---

## Advanced Logic Flows

### 1. Payload Generation & Prioritization Flow

```
Parameter Extraction
        │
        ▼
┌───────────────────────┐
│  PayloadManager       │
│  getAdvancedPayloads()│
└───────────┬───────────┘
            │
            ├─> Step 1: Simple Payloads (FIRST)
            │   └─> <script>alert(1)</script>
            │   └─> <img src=x onerror=alert(1)>
            │
            ├─> Step 2: Core XSS Payloads
            │   └─> CORE_XSS_PAYLOADS
            │
            ├─> Step 3: Advanced Payloads
            │   └─> ADVANCED_XSS_PAYLOADS
            │
            ├─> Step 4: Application-Type Specific
            │   └─> ApplicationTypeSpecificPayloadGenerator
            │       └─> React payloads
            │       └─> Vue payloads
            │       └─> Angular payloads
            │       └─> GraphQL payloads
            │
            ├─> Step 5: Content-Type Specific
            │   └─> ContentSpecificPayloadGenerator
            │       └─> HTML context payloads
            │       └─> JavaScript context payloads
            │       └─> JSON context payloads
            │
            ├─> Step 6: UI-Enabled Payload Packs
            │   ├─> WAF Bypass (if enabled)
            │   ├─> Framework Specific (if enabled)
            │   ├─> Encoding Bypass (if enabled)
            │   ├─> Polyglot Payloads (if enabled)
            │   ├─> Browser-Specific (if enabled)
            │   ├─> JSFucker (if enabled)
            │   ├─> Prototype Pollution (if enabled)
            │   ├─> PostMessage XSS (if enabled)
            │   ├─> Web Components (if enabled)
            │   ├─> Shadow DOM (if enabled)
            │   ├─> WebAssembly (if enabled)
            │   └─> Modern Browser API (if enabled)
            │
            ├─> Step 7: Real-Time Dynamic Payloads
            │   └─> MutationObserver payloads
            │   └─> WebSocket payloads
            │   └─> ServiceWorker payloads
            │   └─> Dynamic Import payloads
            │
            └─> Step 8: Encoding Variants (if enabled)
                └─> URL encoding
                └─> HTML entity encoding
                └─> Unicode encoding
                └─> JSON encoding
            │
            ▼
┌───────────────────────┐
│  Payload Prioritization│
│  PayloadSuccessTracker│
└───────────┬───────────┘
            │
            ├─> Prioritize by Success Rate
            ├─> Prioritize by Application Type
            ├─> Prioritize by Context
            └─> Add Recent Successes to Front
```

### 2. Exploit Validation Flow

```
Payload Injection
        │
        ▼
┌───────────────────────┐
│  Make Request         │
│  with Payload         │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Analyze Response     │
└───────────┬───────────┘
            │
            ├─> Check Payload Reflection
            │   └─> Is payload in response?
            │
            ├─> Check Execution Context
            │   ├─> HTML context?
            │   ├─> JavaScript context?
            │   ├─> Attribute context?
            │   └─> JSON context?
            │
            ├─> Check Encoding
            │   ├─> Is payload encoded?
            │   └─> Can encoding be bypassed?
            │
            ├─> Check WAF Bypass
            │   └─> Did WAF bypass work?
            │
            └─> Check Context Validation
                └─> Is context analysis valid?
            │
            ▼
┌───────────────────────┐
│  AdvancedFiltering    │
│  Engine               │
│  isVulnerabilityTruly  │
│  Exploitable()        │
└───────────┬───────────┘
            │
            ├─> CONFIRMED_XSS = true/false
            ├─> CONFIDENCE_SCORE = 0-100
            └─> XSS_SCORE = 0-100
```

### 3. DOM XSS Detection Flow

```
HTTP Response Analysis
        │
        ▼
┌───────────────────────┐
│  EnhancedDOMXSS       │
│  Detector             │
│  analyzeDOMXSS()      │
└───────────┬───────────┘
            │
            ├─> Extract JavaScript Code
            │   └─> Parse <script> tags
            │   └─> Parse inline scripts
            │   └─> Parse external scripts
            │
            ├─> Detect DOM Sources
            │   ├─> location.href, location.search
            │   ├─> postMessage handlers
            │   ├─> URLSearchParams
            │   ├─> React Router params
            │   ├─> Vue Router params
            │   └─> Framework-specific sources
            │
            ├─> Detect DOM Sinks
            │   ├─> innerHTML, outerHTML
            │   ├─> eval(), Function()
            │   ├─> dangerouslySetInnerHTML
            │   ├─> v-html, [innerHTML]
            │   └─> Framework-specific sinks
            │
            ├─> Analyze Data Flows
            │   └─> Source → Sink correlation
            │   └─> Taint flow analysis
            │
            ├─> Real-Time Dynamic Analysis
            │   ├─> WebSocket detection
            │   ├─> ServiceWorker detection
            │   ├─> MutationObserver detection
            │   ├─> Dynamic Import detection
            │   └─> WebAssembly detection
            │
            ├─> Calculate Vulnerability Score
            │   └─> Risk assessment (0-100)
            │
            └─> Generate Exploit POC
                └─> Browser exploit code
                └─> Reproduction steps
            │
            ▼
┌───────────────────────┐
│  Validation           │
│  - Source-Sink Corr   │
│  - Payload Reflection │
│  - High Confidence     │
└───────────────────────┘
```

### 4. Issue Creation Flow

```
Vulnerability Detection Result
        │
        ▼
┌───────────────────────┐
│  createVulnerability  │
│  Data()               │
└───────────┬───────────┘
            │
            ├─> Extract Detection Data
            │   ├─> Payload
            │   ├─> Test Request/Response
            │   ├─> Confidence Score
            │   ├─> Risk Level
            │   └─> Context Information
            │
            ▼
┌───────────────────────┐
│  EnhancedIssueReporter│
│  createEnhancedXSSIssue│
└───────────┬───────────┘
            │
            ├─> Validate Vulnerability
            │   └─> isVulnerabilityTrulyExploitable()
            │
            ├─> Calculate Severity
            │   └─> CRITICAL, HIGH, MEDIUM, LOW
            │
            ├─> Calculate Confidence
            │   └─> CERTAIN, FIRM, TENTATIVE
            │
            ├─> Generate Issue Name
            │   └─> Context-aware naming
            │
            ├─> Generate Advisory Detail
            │   └─> Burp-safe HTML
            │   └─> Exploit POC
            │   └─> Reproduction steps
            │
            ├─> Generate Issue Background
            │   └─> Vulnerability description
            │
            ├─> Generate Remediation
            │   └─> Fix recommendations
            │
            └─> Create EnhancedScanIssue
                └─> Burp Suite integration
```

---

## Data Structures & Models

### 1. Parameter Map Structure
```java
Map<String, Object> parameter = {
    "NAME": "parameter_name",
    "VALUE": "parameter_value",
    "TYPE": "URL|BODY|COOKIE|HEADER",
    "VALUE_START": int,
    "VALUE_END": int,
    "REFLECTED_IN": "HEADERS|BODY|BOTH",
    "VULNERABLE": boolean,
    "CONTENT_TYPE": "text/html",
    "REFLECTION_CONTEXT": "HTML|JavaScript|Attribute|JSON",
    "APPLICATION_TYPE": "REACT|VUE|ANGULAR|GRAPHQL|SPA",
    "ARCH_ANALYSIS": ArchitectureAnalysis,
    "TEST_REQUEST": byte[],
    "TEST_RESPONSE": byte[],
    "PAYLOAD": "test_payload",
    "CONFIRMED_XSS": boolean,
    "CONFIDENCE_SCORE": double,
    "XSS_SCORE": double
}
```

### 2. Vulnerability Data Structure
```java
Map<String, Object> vulnerabilityData = {
    "vulnerabilityType": "XSS|DOM XSS|Client-Side XSS",
    "payload": "exploit_payload",
    "testPayload": "test_payload",
    "testRequest": byte[],
    "testResponse": byte[],
    "TEST_REQUEST": byte[],
    "TEST_RESPONSE": byte[],
    "paramName": "parameter_name",
    "CONFIRMED_XSS": boolean,
    "CONFIDENCE_SCORE": double,
    "XSS_SCORE": double,
    "ENHANCED_CONTEXT": "context_description",
    "SCAN_TYPE": "DOM|Client-Side Attack|Reflected",
    "EXPLOIT_POC": "proof_of_concept_code",
    "REPRODUCTION_STEPS": "step_by_step_instructions",
    "SOURCE_SINK_ANALYSIS": "analysis_text",
    "BROWSER_EXPLOIT_CODE": "browser_code",
    "HIGHLIGHT_TERMS": List<String>
}
```

### 3. DOMXSSResult Structure
```java
class DOMXSSResult {
    boolean vulnerable;
    String confidenceLevel;        // "Certain", "Firm", "Tentative"
    String riskLevel;              // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    int vulnerabilityScore;       // 0-100
    String testPayload;
    String testRequest;
    String testResponse;
    List<DOMSource> detectedSources;
    List<DOMSink> detectedSinks;
    List<DataFlow> dataFlows;
    String sourceSinkAnalysis;
    String exploitPOC;
    String reproductionSteps;
    String browserExploitCode;
    RealTimeDynamicAnalysis realTimeAnalysis;
}
```

### 4. ClientSideAttackResult Structure
```java
class ClientSideAttackResult {
    boolean vulnerable;
    String confidenceLevel;
    String riskLevel;
    int riskScore;                 // 0-100
    String testPayload;
    String testRequest;
    String testResponse;
    CSPAnalysis cspAnalysis;
    PostMessageAnalysis postMessageAnalysis;
    WebSocketAnalysis webSocketAnalysis;
    TemplateInjectionAnalysis templateInjectionAnalysis;
    PrototypePollutionAnalysis prototypePollutionAnalysis;
    ModernAPIAnalysis modernAPIAnalysis;
    WebComponentsAnalysis webComponentsAnalysis;
    String exploitPOC;
    String reproductionSteps;
}
```

### 5. ArchitectureAnalysis Structure
```java
class ArchitectureAnalysis {
    String primaryArchitecture;    // "SPA", "JAMStack", "Microservices", etc.
    String riskLevel;              // "HIGH", "MEDIUM", "LOW"
    List<String> detectedFrameworks;
    boolean hasGraphQL;
    boolean isSPA;
    boolean isMicroservices;
    boolean isJAMStack;
    Map<String, Object> frameworkVersions;
}
```

---

## Integration Points

### 1. Burp Suite Integration

**Interfaces Implemented:**
- `IBurpExtender` - Extension registration
- `IScannerCheck` - Scanner integration
- `ITab` - UI tab integration

**Key Integration Points:**
```java
// Extension registration
callbacks.setExtensionName("XSSDetector v2.0.0");
callbacks.registerScannerCheck(this);
callbacks.addSuiteTab(this);

// Issue creation
IScanIssue issue = new EnhancedScanIssue(
    httpService,
    url,
    httpMessages,
    issueName,
    advisoryDetail,
    severity,
    confidence,
    remediationDetail,
    issueBackground
);
```

### 2. Settings Integration

**Settings Persistence:**
- All settings saved via `callbacks.saveExtensionSetting()`
- All settings loaded via `callbacks.loadExtensionSetting()`
- Content types stored as serialized array

**Settings Categories:**
- Core Detection: scopeOnly, aggressiveMode, checkContext
- Modern Detection: modernDetection, domXssDetection, cspAnalysis
- Advanced Features: WAF bypass, framework-specific, encoding bypass, etc.
- Payload Packs: JSFucker, Prototype Pollution, PostMessage, Web Components, etc.
- Reporting: detailedReporting, exploitGeneration, verboseLogging

### 3. Performance Monitoring

**PerformanceMonitor Integration:**
- Tracks scan performance metrics
- Monitors memory usage
- Tracks detection engine performance
- Used by ErrorRecoverySystem for error handling

### 4. Error Recovery

**ErrorRecoverySystem Integration:**
- Handles exceptions gracefully
- Recovers from errors
- Logs errors with context
- Prevents scan interruption

---

## Payload Management System

### Payload Categories

1. **Core Payloads** (`CORE_XSS_PAYLOADS`)
   - Basic HTML context payloads
   - Attribute context payloads
   - JavaScript context payloads
   - URL context payloads

2. **Advanced Payloads** (`ADVANCED_XSS_PAYLOADS`)
   - Advanced encoding bypasses
   - Event handler variations
   - CSS injection
   - SVG injection

3. **WAF Bypass Payloads** (`WAF_BYPASS_PAYLOADS`)
   - Case swapping
   - Unicode encoding
   - String concatenation
   - Hex encoding

4. **Framework-Specific Payloads** (`FRAMEWORK_SPECIFIC_PAYLOADS`)
   - React payloads
   - Vue payloads
   - Angular payloads
   - Template injection payloads

5. **Modern Browser API Payloads**
   - WebSocket payloads
   - ServiceWorker payloads
   - WebAssembly payloads
   - Trusted Types bypass
   - Sanitizer API bypass
   - DOMPurify bypass

6. **Specialized Payloads**
   - JSFucker obfuscated
   - Prototype Pollution
   - PostMessage XSS
   - Web Components
   - Shadow DOM
   - Mutation XSS (mXSS)
   - Universal XSS (uXSS)

### Payload Prioritization

**Priority Factors:**
1. Success rate (from `PayloadSuccessTracker`)
2. Application type match
3. Context match
4. Recent successes
5. Simplicity (simple payloads tried first)

---

## Issue Reporting Pipeline

### Issue Creation Process

1. **Detection** → Vulnerability detected by engine
2. **Validation** → `AdvancedFilteringEngine` validates exploit
3. **Data Collection** → `createVulnerabilityData()` collects evidence
4. **Issue Generation** → `EnhancedIssueReporter.createEnhancedXSSIssue()`
5. **Severity Calculation** → Based on context, exploitability, impact
6. **Confidence Calculation** → Based on evidence strength
7. **Advisory Generation** → Burp-safe HTML with exploit POC
8. **Remediation Generation** → Fix recommendations
9. **Issue Creation** → `EnhancedScanIssue` object
10. **Consolidation** → `consolidateDuplicateIssues()` prevents duplicates

### Issue Validation

**Validation Checks:**
- Payload reflection in response
- Execution context validation
- Encoding bypass confirmation
- WAF bypass confirmation
- Context analysis validation
- Source-sink correlation (for DOM XSS)
- Real-time vector detection (for client-side)

**False Positive Filters:**
- CSP misconfiguration alone (not exploitable XSS)
- Pattern matching without data flow
- Insufficient evidence
- Low confidence scores

---

## Advanced Features

### 1. Response Caching
- Caches HTTP responses to reduce redundant requests
- Tracks cache hits/misses
- Improves scan performance

### 2. Payload Success Tracking
- Tracks successful payloads per application type
- Tracks successful payloads per context
- Prioritizes successful payloads in future scans

### 3. Parameter Reflection Tracking
- Tracks which parameters reflect
- Tracks which parameters don't reflect
- Skips non-reflecting parameters in future scans

### 4. Real-Time Dynamic Analysis
- Detects WebSocket usage
- Detects ServiceWorker usage
- Detects MutationObserver usage
- Detects Dynamic Import usage
- Generates real-time-specific payloads

### 5. Session Handling
- Automatic CSRF token extraction
- Automatic session token management
- Session validation

---

## File Structure

```
src/burp/
├── BurpExtender.java                    # Main entry point
├── Settings.java                        # Settings management
├── Constants.java                       # Constants & payloads
├── CheckReflection.java                 # Core reflection detection
├── EnhancedAggressive.java              # Active detection engine
├── EnhancedDOMXSSDetector.java          # DOM XSS detection
├── EnhancedClientSideAttackDetector.java # Client-side attacks
├── ModernArchitectureDetector.java     # Architecture analysis
├── AdvancedJSONAnalyzer.java           # JSON analysis
├── AIContextAnalyzer.java              # AI context analysis
├── EngineIntegrationManager.java       # Engine orchestration
├── AdvancedFilteringEngine.java        # False positive reduction
├── EnhancedIssueReporter.java          # Issue creation
├── PayloadManager.java                 # Payload management
├── ApplicationTypeSpecificPayloadGenerator.java
├── ContentSpecificPayloadGenerator.java
├── ModernParameterExtractor.java       # Parameter extraction
├── ParameterReflectionTracker.java     # Reflection tracking
├── PayloadSuccessTracker.java          # Success tracking
├── ResponseCache.java                  # Response caching
├── SessionHandlingManager.java         # Session management
├── PerformanceMonitor.java            # Performance monitoring
├── ErrorRecoverySystem.java           # Error recovery
└── [Burp API Interfaces]              # Burp Suite interfaces
```

---

## Summary

XSSDetector implements a **comprehensive, multi-engine XSS detection system** with:

1. **Foundation Engine** (`CheckReflection`) - Core reflection detection
2. **Active Engine** (`EnhancedAggressive`) - Advanced active scanning
3. **DOM XSS Engine** (`EnhancedDOMXSSDetector`) - Client-side DOM XSS
4. **Client-Side Engine** (`EnhancedClientSideAttackDetector`) - Modern client-side attacks
5. **Architecture Analysis** (`ModernArchitectureDetector`) - Framework detection
6. **Filtering Engine** (`AdvancedFilteringEngine`) - False positive reduction
7. **Issue Reporting** (`EnhancedIssueReporter`) - Professional issue creation

**Key Features:**
- Context-aware payload generation
- Application-type-specific payloads
- Real-time dynamic analysis
- Advanced false positive reduction
- Comprehensive framework support
- Professional issue reporting with exploit POCs

**Performance Optimizations:**
- Response caching
- Payload success tracking
- Parameter reflection tracking
- Performance monitoring
- Error recovery

This architecture provides **maximum detection coverage** while maintaining **high accuracy** through advanced validation and filtering.
