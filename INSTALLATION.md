# XSSDetector Installation Guide

## Prerequisites

- **Burp Suite Professional** (2023.1 or later)
- **Java Runtime Environment (JRE)** 8 or later
- **Windows/Linux/macOS** operating system

## Installation Steps

### 1. Download XSSDetector

Download the latest `XSSDetector.jar` file from the releases page or build it from source.

### 2. Install in Burp Suite

1. **Open Burp Suite Professional**
2. **Navigate to Extensions tab**
3. **Click "Add" button**
4. **Select "Java" as extension type**
5. **Browse and select `XSSDetector.jar`**
6. **Click "Next" and then "Close"**

### 3. Verify Installation

1. **Check Extensions tab** - XSSDetector should appear in the list
2. **Look for "XSSDetector" tab** in the main interface
3. **Verify no error messages** in the Extensions output

## Configuration

### Initial Setup

1. **Open XSSDetector tab**
2. **Configure scan settings**:
   - Enable/disable detection engines
   - Set scan intensity levels
   - Configure payload categories
3. **Set scope** - Define target URLs for scanning
4. **Save settings**

### Advanced Configuration

- **Detection Engines**: Enable specific XSS detection methods
- **Payload Management**: Customize payload categories and priorities
- **Performance Settings**: Adjust scan speed and resource usage
- **Reporting Options**: Configure issue severity and confidence levels

## Usage

### Basic Scanning

1. **Set target scope** in Burp Suite
2. **Navigate to XSSDetector tab**
3. **Click "Start Scan"**
4. **Monitor progress** in the scan results
5. **Review findings** in Issues tab

### Advanced Features

- **Real-time Detection**: Continuous monitoring of requests/responses
- **Context Analysis**: Advanced payload reflection analysis
- **JSON/API Support**: Modern web application detection
- **Professional Reporting**: Burp Suite compliant advisories

## Troubleshooting

### Common Issues

**Extension not loading:**
- Verify Java version compatibility
- Check JAR file integrity
- Ensure Burp Suite version is supported

**Scan not working:**
- Verify target scope is set
- Check network connectivity
- Review extension logs for errors

**No findings detected:**
- Verify target is vulnerable to XSS
- Check scan settings and intensity
- Review payload configuration

### Support

For issues and questions:
- Check the [README.md](README.md) for detailed documentation
- Review [CHANGELOG.md](CHANGELOG.md) for recent changes
- Open an issue on GitHub for bug reports

## Security Notes

- **Use responsibly** - Only test applications you own or have permission to test
- **Follow ethical guidelines** - Respect privacy and legal requirements
- **Report vulnerabilities** - Help improve application security
- **Keep updated** - Use latest version for best security coverage

## Performance Tips

- **Optimize scope** - Limit scanning to relevant targets
- **Adjust intensity** - Balance speed vs. thoroughness
- **Monitor resources** - Watch CPU and memory usage
- **Batch scanning** - Group similar targets for efficiency 