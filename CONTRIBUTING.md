# Contributing to XSSDetector

Thank you for your interest in contributing to XSSDetector! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

There are many ways to contribute to XSSDetector:

- **🐛 Report Bugs**: Help us identify and fix issues
- **💡 Suggest Features**: Propose new features and improvements
- **📝 Improve Documentation**: Help make our docs better
- **🔧 Submit Code**: Contribute code improvements and new features
- **🧪 Test**: Help test new features and bug fixes
- **📢 Share**: Spread the word about XSSDetector

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Contributions](#security-contributions)
- [Community Guidelines](#community-guidelines)

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Java 8 or higher** (Java 11+ recommended)
- **Git** for version control
- **Burp Suite Professional** for testing
- **IDE** (IntelliJ IDEA, Eclipse, or VS Code)
- **Basic knowledge** of Java and web security

### Quick Start

1. **Fork the Repository**
   ```bash
   git clone https://github.com/your-username/XSSDetector.git
   cd XSSDetector
   ```

2. **Set up Development Environment**
   ```bash
   # Install dependencies (if any)
   # Configure your IDE
   # Set up Burp Suite for testing
   ```

3. **Make Your Changes**
   ```bash
   # Create a feature branch
   git checkout -b feature/your-feature-name
   
   # Make your changes
   # Test thoroughly
   # Commit your changes
   ```

4. **Submit Your Contribution**
   ```bash
   # Push to your fork
   git push origin feature/your-feature-name
   
   # Create a pull request
   ```

## 🛠️ Development Setup

### Environment Configuration

1. **Java Setup**
   ```bash
   # Verify Java installation
   java -version
   javac -version
   
   # Set JAVA_HOME if needed
   export JAVA_HOME=/path/to/your/java
   ```

2. **IDE Configuration**
   - **IntelliJ IDEA**: Import as Maven/Gradle project or Java project
   - **Eclipse**: Import as Java project
   - **VS Code**: Install Java extension pack

3. **Burp Suite Setup**
   - Install Burp Suite Professional
   - Configure for development testing
   - Set up test applications

### Build Process

```bash
# Build on Linux/macOS
chmod +x build.sh
./build.sh

# Build on Windows
build.bat

# Verify build
ls -la dist/XSSDetector.jar
```

### Testing Setup

```bash
# Run unit tests (when implemented)
./run-tests.sh

# Run integration tests
./run-integration-tests.sh

# Manual testing with Burp Suite
```

## 📝 Code Style Guidelines

### Java Code Style

Follow these Java coding conventions:

```java
// Class naming: PascalCase
public class XSSDetector {
    
    // Constants: UPPER_SNAKE_CASE
    public static final String PLUGIN_NAME = "XSSDetector";
    
    // Variables: camelCase
    private String userName;
    
    // Methods: camelCase
    public void detectXSS() {
        // Implementation
    }
    
    // Boolean methods: is/has/can prefix
    public boolean isVulnerable() {
        return false;
    }
}
```

### Documentation Standards

1. **JavaDoc Comments**
   ```java
   /**
    * Detects XSS vulnerabilities in the given request.
    * 
    * @param request The HTTP request to analyze
    * @param response The HTTP response to analyze
    * @return List of detected vulnerabilities
    * @throws SecurityException if security check fails
    */
   public List<Vulnerability> detectXSS(HttpRequest request, HttpResponse response) {
       // Implementation
   }
   ```

2. **Inline Comments**
   ```java
   // Check for reflected parameters in response
   if (response.contains(payload)) {
       // Validate context to reduce false positives
       String context = analyzeContext(response, payload);
       if (isVulnerableContext(context)) {
           return createVulnerability(request, payload, context);
       }
   }
   ```

### File Organization

```
src/burp/
├── BurpExtender.java          # Main extension class
├── Constants.java             # Constants and configuration
├── Settings.java              # Settings management
├── detection/                 # Detection engine classes
├── ui/                        # User interface classes
├── utils/                     # Utility classes
└── reporting/                 # Reporting classes
```

## 🧪 Testing Guidelines

### Unit Testing

```java
@Test
public void testXSSDetection() {
    // Arrange
    HttpRequest request = createTestRequest();
    HttpResponse response = createTestResponse();
    
    // Act
    List<Vulnerability> vulnerabilities = detector.detectXSS(request, response);
    
    // Assert
    assertThat(vulnerabilities).hasSize(1);
    assertThat(vulnerabilities.get(0).getType()).isEqualTo("XSS");
}
```

### Integration Testing

```java
@Test
public void testBurpIntegration() {
    // Test integration with Burp Suite
    // Verify extension loads correctly
    // Test scanning functionality
}
```

### Manual Testing

1. **Load Extension**: Test loading into Burp Suite
2. **Basic Functionality**: Test basic XSS detection
3. **Advanced Features**: Test advanced detection features
4. **Performance**: Test with large applications
5. **Error Handling**: Test error scenarios

### Test Coverage

- **Unit Tests**: 80%+ code coverage
- **Integration Tests**: All major features
- **Manual Tests**: User workflows
- **Performance Tests**: Load testing

## 🔄 Pull Request Process

### Before Submitting

1. **Code Quality**
   - [ ] Follows coding standards
   - [ ] No compiler warnings
   - [ ] Proper error handling
   - [ ] Input validation

2. **Testing**
   - [ ] Unit tests pass
   - [ ] Integration tests pass
   - [ ] Manual testing completed
   - [ ] Cross-platform testing

3. **Documentation**
   - [ ] Code documented
   - [ ] README updated (if needed)
   - [ ] CHANGELOG updated (if needed)

### Pull Request Template

Use the provided pull request template and fill in all sections:

- **Description**: Clear description of changes
- **Testing**: Test results and coverage
- **Documentation**: Documentation updates
- **Screenshots**: UI changes (if applicable)

### Review Process

1. **Automated Checks**: CI/CD pipeline runs
2. **Code Review**: Maintainers review code
3. **Testing**: Additional testing if needed
4. **Approval**: Changes approved and merged

## 🐛 Issue Reporting

### Bug Reports

Use the bug report template and include:

- **Clear Description**: What the bug is
- **Steps to Reproduce**: How to reproduce
- **Expected vs Actual**: What should vs what happens
- **Environment**: System details
- **Screenshots**: Visual evidence

### Feature Requests

Use the feature request template and include:

- **Problem Statement**: What problem it solves
- **Proposed Solution**: How to implement
- **Use Cases**: Real-world scenarios
- **Impact Assessment**: Benefits and priority

### Security Issues

For security vulnerabilities:

- **Private Reporting**: Use security advisory
- **Responsible Disclosure**: Coordinate timeline
- **Detailed Information**: Proof of concept
- **Impact Assessment**: Severity and scope

## 🔒 Security Contributions

### Security Research

When contributing security-related code:

1. **Follow Best Practices**
   - Input validation
   - Secure coding practices
   - Error handling
   - Access controls

2. **Testing Security**
   - Penetration testing
   - Vulnerability assessment
   - Security code review

3. **Documentation**
   - Security considerations
   - Threat models
   - Mitigation strategies

### Responsible Disclosure

- Report vulnerabilities privately
- Allow time for fixes
- Coordinate disclosure
- Follow ethical guidelines

## 👥 Community Guidelines

### Communication

- **Be Respectful**: Treat others with respect
- **Be Constructive**: Provide helpful feedback
- **Be Patient**: Allow time for responses
- **Be Professional**: Maintain professional conduct

### Collaboration

- **Share Knowledge**: Help others learn
- **Mentor Newcomers**: Guide new contributors
- **Review Code**: Help review pull requests
- **Test Features**: Help test new features

### Recognition

- **Credit Contributors**: Acknowledge contributions
- **Hall of Fame**: Recognize significant contributors
- **Documentation**: Credit in documentation
- **Releases**: Mention in release notes

## 📚 Resources

### Documentation

- [README.md](README.md) - Project overview
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [SECURITY.md](SECURITY.md) - Security policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community guidelines

### External Resources

- [OWASP Guidelines](https://owasp.org/) - Security best practices
- [Java Documentation](https://docs.oracle.com/javase/) - Java reference
- [Burp Suite Documentation](https://portswigger.net/burp/documentation) - Burp Suite reference

### Tools

- [SonarQube](https://www.sonarqube.org/) - Code quality
- [SpotBugs](https://spotbugs.github.io/) - Bug detection
- [Checkstyle](https://checkstyle.sourceforge.io/) - Code style

## 🏆 Recognition

### Contributor Levels

- **Newcomer**: First contribution
- **Regular**: Multiple contributions
- **Core**: Significant contributions
- **Maintainer**: Project maintenance

### Hall of Fame

Contributors who have made significant contributions:

- [To be populated based on contributions]

## 📞 Contact

For questions about contributing:

- **GitHub Issues**: [Create an issue](https://github.com/vikaskumar/XSSDetector/issues)
- **Discussions**: [Join discussions](https://github.com/vikaskumar/XSSDetector/discussions)
- **Email**: [Contact via GitHub](https://github.com/vikaskumar/XSSDetector/issues)

## 🙏 Acknowledgments

Thank you to all contributors who help make XSSDetector better! Your contributions are valuable and appreciated.

---

**Happy contributing!** 🛡️ 