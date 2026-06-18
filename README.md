# XSSDetector - Advanced XSS Vulnerability Scanner for Burp Suite

<div align="center">
   
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Java](https://img.shields.io/badge/Java-8%2B-blue.svg)](https://www.oracle.com/java/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-2023.1%2B-orange.svg)](https://portswigger.net/burp)
[![Version](https://img.shields.io/badge/Version-2.0.0--Production%20Ready-green.svg)](https://github.com/infosec-lab/XSSDetector/releases)

*A comprehensive Burp Suite extension for detecting all forms of XSS, client-side injections, and SPA/API abuse using advanced payloads, encoding, and bypass techniques.*

> _**Note**: Currently in active development. Core detection engines are fully functional. Additional UI enhancements and integrations planned for future releases._

</div>

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Advanced Features](#advanced-features)
- [Detection Capabilities](#detection-capabilities)
- [Performance](#performance)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

## Features

### Core Detection Engine
- **Context-Aware Analysis** - Payload selection driven by reflection context (HTML, attribute, JS, CSS, URL)
- **Reflection & Exploit Validation** - Confirms payloads are reflected unencoded before reporting, reducing false positives
- **Modern Framework Awareness** - Detects React, Angular, Vue.js, GraphQL and WebSocket usage to tune analysis
- **WAF/Filter Bypass** - Encoding and mutation techniques to get past common input filters
- **DOM XSS Detection** - Source-to-sink data-flow analysis for client-side sinks

### Advanced Capabilities
- **Polyglot Payloads** - Multi-context attack vectors
- **Encoding Techniques** - Unicode, Base64, and URL encoding variants
- **Template Injection Detection** - Client-side template and expression patterns
- **Modern Browser API Heuristics** - Optional Service Worker / WebAssembly / Shadow DOM payload options
- **Session Handling** - CSRF token and session management for authenticated scans

### Reporting & Integration
- **Detailed HTML Issue Reports** - Payload, reflection context, exploit PoC, steps to reproduce, impact and remediation
- **Confidence Scoring** - Each finding carries a confidence score with a configurable reporting threshold
- **Deduplication** - Filters duplicate findings across passive/active scans
- **Burp Integration** - Passive scanner, active scanner, and real-time proxy analysis

## Screenshots

### Scanner Settings & Configuration
![Scanner Settings](screenshot/1.Scanner_Settings.png)
*Comprehensive configuration panel with advanced detection options, encoding techniques, and performance controls.*

### Detection Results & Analysis
![Detection Results](screenshot/2.Detections.png)
*Real-time vulnerability detection with context-aware analysis and confidence scoring.*

### Advanced Encoding Techniques
![Encoding Analysis](screenshot/3.Encoding.png)
*Multi-layer encoding detection with bypass strategies and statistical analysis.*

### Detailed Results & Reporting
![Results Dashboard](screenshot/4.Results.png)
*Professional vulnerability reporting with exploit generation and remediation guidance.*

## Installation

### Prerequisites
- **Java 11 or higher** (required for building; JAR is compiled for Java 11 compatibility)
- **Burp Suite Professional 2023.1 or higher**
- **Windows, macOS, or Linux**

### Quick Installation

1. **Download the Latest Release**
   ```bash
   # Clone the repository
   git clone https://github.com/infosec-lab/XSSDetector.git
   cd XSSDetector
   
   # Build the extension
   ./build.sh  # Linux/macOS
   # OR
   build.bat   # Windows
   ```

2. **Load into Burp Suite**
   - Open Burp Suite Professional
   - Go to **Extender** > **Extensions** > **Add**
   - Select **Java** as the extension type
   - Browse to `dist/XSSDetector.jar`
   - Click **Next** and **Close**

3. **Verify Installation**
   - Check the **XSSDetector** tab appears in Burp Suite
   - Verify the extension loads without errors in the **Extender** > **Output** tab

### Automated Build (GitHub Actions)
A GitHub Actions workflow compiles the extension and produces the JAR on every
push and pull request:

```yaml
# Build matrix:
# - Operating Systems: Ubuntu, Windows, macOS
# - Java Versions: 11, 17
```

## Quick Start

### Basic Usage
1. **Configure Target Scope**
   - Set your target application in Burp Suite's scope
   - Enable "Scope only" in XSSDetector settings

2. **Configure Detection Options**
   In the **XSSDetector** tab, enable the checks you need:
   - **Modern Detection**: Framework-aware (React/Angular/Vue/GraphQL/WebSocket) analysis
   - **DOM XSS Detection**: Client-side source-to-sink analysis
   - **Aggressive/Active Scanning**: Sends payloads with encoding and filter-bypass variants
   - **Encoding Options**: Unicode, Base64, and URL encoding toggles
   - **Scope Only**: Restrict scanning to your Burp target scope

3. **Start Scanning**
   - Use Burp Suite's **Active Scanner** or **Spider**
   - XSSDetector automatically analyzes requests and responses
   - View results in the **Issues** tab

### Advanced Configuration

#### Context-Aware Detection
```java
// Enable deep context analysis
deepContextAnalysis.setSelected(true);
behavioralAnalysis.setSelected(true);
semanticAnalysis.setSelected(true);
```

#### Modern Framework Detection
```java
// Enable framework-specific detection
modernDetection.setSelected(true);
domXssDetection.setSelected(true);
cspAnalysis.setSelected(true);
```

#### Performance Optimization
```java
// Configure thread pool for optimal performance
encodingDetectionThreads.setValue(5);
encodingCacheSize.setValue(1000);
enableEncodingOptimization.setSelected(true);
```

## Advanced Features

### Context Analysis
- **Context Recognition**: Identifies HTML, JavaScript, CSS, and attribute contexts via heuristic pattern analysis
- **Payload Selection**: Chooses payloads based on the detected reflection context
- **False Positive Reduction**: Multi-layer validation (reflection checks, safe-context detection, confidence thresholds)
- **Confidence Scoring**: Risk assessment based on multiple factors

### Modern Attack Vectors
- **GraphQL Injection**: Query and mutation parameter testing
- **WebSocket XSS**: Real-time communication channel exploitation
- **SPA Framework Attacks**: React, Angular, and Vue.js specific payloads
- **Template Injection**: Server-side and client-side template attacks

### Evasion Techniques
- **WAF/Filter Bypass**: Multiple techniques to get past common input filters
- **Encoding Variants**: Unicode, Base64, and URL encoding combinations
- **Browser-Specific**: Payload variants targeting different browser parsing quirks
- **Polyglot Payloads**: Multi-context attack vectors

### Reporting
- **Exploit Generation**: Proof-of-concept code (JavaScript, cURL, HTML) for confirmed findings
- **Steps to Reproduce**: Actionable, numbered reproduction steps in every report
- **Remediation Guidance**: Context-specific fix recommendations
- **Risk Assessment**: Severity and impact analysis with OWASP/PortSwigger references

## Detection Capabilities

### Vulnerability Types
| Type | Detection Method |
|------|------------------|
| **Reflected XSS** | Context-aware payload injection with reflection validation |
| **DOM XSS** | Client-side source/sink data-flow analysis |
| **Stored XSS** | Response pattern analysis on persisted input |
| **Template Injection** | Client-side template/expression pattern detection |
| **WAF/Filter Bypass** | Encoding and mutation technique variants |

> Every finding includes a confidence score and is gated behind a configurable
> reporting threshold to reduce false positives. As with any heuristic scanner,
> findings should still be manually validated before disclosure.

### Supported Contexts
- **HTML Context**: `<script>`, `<img>`, `<svg>`, `<iframe>`
- **JavaScript Context**: String literals, function calls, eval()
- **CSS Context**: Style attributes, CSS files, animations
- **Attribute Context**: href, src, on* event handlers
- **URL Context**: Protocol handlers, data URIs
- **Template Context**: Server-side and client-side templates

### Modern Framework Support
- **React**: JSX injection, component props, state manipulation
- **Angular**: Template injection, expression evaluation
- **Vue.js**: Directive injection, computed properties
- **GraphQL**: Query injection, introspection attacks
- **WebSockets**: Real-time communication channel exploitation

## Performance

The extension is built to scan alongside normal Burp usage without overwhelming
the target or the host:

- **Configurable Threading**: Tunable thread pool for encoding/active checks
- **Response Caching**: Avoids re-sending identical test requests
- **Large-Response Guard**: Skips responses over 10 MB to protect memory/performance
- **Rate-Limit Awareness**: Backs off on HTTP 429 and skips on 5xx errors
- **Deduplication**: Suppresses duplicate issues across passive and active scans

> Actual throughput and memory use depend on target, scope, network latency,
> and the options you enable. No fixed performance figures are guaranteed.

## Development

### Project Structure
```
XSSDetector/
  src/burp/                    # Main source code
    BurpExtender.java       # Main extension class
    Constants.java          # Configuration constants
    Settings.java           # Settings management
    AdvancedFilteringEngine.java
    EnhancedDOMXSSDetector.java
    ...                     # Additional components
  build/                      # Build artifacts
  dist/                       # Distribution files
  screenshot/                 # Documentation screenshots
  .github/                    # GitHub workflows and templates
  build.sh                    # Unix build script
  build.bat                   # Windows build script
  README.md                   # This file
```

### Building from Source
```bash
# Prerequisites
java -version  # Java 11 or higher (required)
javac -version # Java compiler (must be Java 11+)

# Build on Linux/macOS
chmod +x build.sh
./build.sh

# Build on Windows
build.bat

# Verify build
ls -la dist/XSSDetector.jar
```

### Development Setup
1. **Clone the Repository**
   ```bash
   git clone https://github.com/infosec-lab/XSSDetector.git
   cd XSSDetector
   ```

2. **Set up Development Environment**
   ```bash
   # Install a Java 11+ Development Kit
   # Open the project in your IDE (IntelliJ IDEA, Eclipse, or VS Code)
   # Install Burp Suite Professional for manual testing
   ```

3. **Build and Test Manually**
   ```bash
   # Compile and package
   ./build.sh

   # Load dist/XSSDetector.jar into Burp and test against a
   # deliberately vulnerable app (e.g. PortSwigger Web Security Academy
   # labs, OWASP Juice Shop, or DVWA)
   ```

> Note: an automated unit/integration test suite is not yet included.
> Contributions adding tests are very welcome.

### Code Quality
- **Inline Documentation**: Components are documented throughout the source
- **Modular Engines**: Detection logic is split into focused, single-responsibility classes
- **Manual Validation**: Findings are validated against reflection evidence before reporting

---

## Contributing

We welcome contributions from the security community! Here's how you can help:

### Contribution Guidelines
1. **Fork the Repository**
2. **Create a Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Make Your Changes**: Follow the coding standards
4. **Test Thoroughly**: Ensure all tests pass
5. **Submit a Pull Request**: With detailed description

### Development Standards
- **Code Style**: Follow Java conventions
- **Documentation**: Add comments for complex logic
- **Testing**: Include unit tests for new features
- **Security**: Follow secure coding practices

### Issue Reporting
- **Bug Reports**: Include steps to reproduce
- **Feature Requests**: Describe use case and benefits
- **Security Issues**: Report privately if sensitive

### Community Guidelines
- **Respectful Communication**: Be professional and constructive
- **Knowledge Sharing**: Help others learn and grow
- **Security Ethics**: Use responsibly and legally

## Credits

**XSSDetector Contributors**  
- **Email**: [infoseclab005@gmail.com](mailto:infoseclab005@gmail.com)  
- **GitHub**: [@infosec-lab](https://github.com/infosec-lab)  

### Special Thanks
- **PortSwigger** - For the excellent Burp Suite platform
- **Security Community** - For feedback, testing, and collaboration
- **Open Source Contributors** - For inspiration and technical guidance
- **AI Development Partners** - For collaborative development assistance

---

<div align="center">

**XSSDetector** - Advanced XSS Vulnerability Scanner for Burp Suite

*Built with ❤️ for the security community*

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/infosec-lab/XSSDetector)

</div> 
