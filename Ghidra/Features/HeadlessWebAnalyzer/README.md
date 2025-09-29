# Ghidra Headless Web Analyzer

A comprehensive web-based malware analysis platform built on top of Ghidra's headless analyzer capabilities.

## Features

### 🔍 Core Analysis Capabilities
- **File Analysis**: Upload and analyze malware samples using Ghidra's powerful analysis engine
- **Custom Commands**: Execute user-defined headless Ghidra commands with full parameter control
- **IOC Extraction**: Automatically extract Indicators of Compromise including:
  - IP addresses and domains
  - URLs and network endpoints  
  - Registry keys and mutex names
  - File hashes and crypto keys

### 📋 Pre-configured Workflows
- **Basic Malware Analysis**: Standard analysis with function identification
- **Advanced Obfuscated Analysis**: Deep analysis for packed/obfuscated samples
- **Network Behavior Analysis**: Focus on C2 communication patterns
- **Ransomware Analysis**: Specialized analysis for ransomware samples
- **API Analysis**: Comprehensive Windows API usage analysis

### 🔄 Batch Processing
- Process multiple files simultaneously
- Directory-based batch analysis
- Progress tracking and status monitoring
- Detailed reporting for each sample

### 📊 Malware Categorization
- Automatic malware type classification
- Organized storage by malware family
- Pattern-based categorization system
- Custom category definitions

### 🤖 ML/AI Integration
- Code pattern analysis using Deep Learning models
- Automated deobfuscation capabilities
- Malware family classification
- Obfuscation technique detection

## Quick Start

### Running the Web Application

```bash
# Build the project
./gradlew :HeadlessWebAnalyzer:build

# Run the web application
java -cp "build/libs/*" ghidra.features.headlessweb.MalwareAnalysisWebApp [port]
```

Default port is 8080. Access the web interface at `http://localhost:8080`

### API Usage Examples

#### Upload and Analyze a File
```bash
curl -X POST -F "file=@malware.exe" http://localhost:8080/api/analyze/file
```

#### Execute Custom Headless Command
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"command":"analyzeHeadless /tmp/project TestProject -import malware.exe -postScript ExtractIOCs.java"}' \
  http://localhost:8080/api/analyze/custom
```

#### Get Analysis Results
```bash
curl http://localhost:8080/api/analyze/result/{analysis-id}
```

#### Extract IOCs
```bash
curl http://localhost:8080/api/extract/iocs/{analysis-id}
```

#### Execute Workflow
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"workflowId":"basic-malware-analysis", "filePath":"/path/to/malware.exe"}' \
  http://localhost:8080/api/workflows/execute
```

#### Batch Analysis
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"filePaths":["/path/to/malware1.exe", "/path/to/malware2.exe"]}' \
  http://localhost:8080/api/batch/analyze
```

## API Reference

### Analysis Endpoints
- `POST /api/analyze/file` - Upload and analyze a file
- `POST /api/analyze/custom` - Execute custom headless command
- `GET /api/analyze/status/{id}` - Get analysis status
- `GET /api/analyze/result/{id}` - Get analysis results
- `GET /api/analyze/results` - Get all analysis results

### Workflow Endpoints
- `GET /api/workflows` - Get available workflows
- `POST /api/workflows/execute` - Execute a workflow
- `GET /api/workflows/{id}/status` - Get workflow status

### Extraction Endpoints
- `GET /api/extract/iocs/{id}` - Extract IOCs from analysis
- `GET /api/extract/functions/{id}` - Extract function calls
- `GET /api/extract/strings/{id}` - Extract interesting strings

### Batch Processing Endpoints
- `POST /api/batch/analyze` - Submit batch analysis
- `GET /api/batch/status/{id}` - Get batch status
- `GET /api/batch/results/{id}` - Get batch results

### Categorization Endpoints
- `GET /api/malware/categories` - Get available categories
- `POST /api/malware/categorize/{id}` - Categorize malware
- `GET /api/malware/category/{category}` - Get malware by category

### ML/AI Endpoints
- `POST /api/ml/analyze-patterns/{id}` - Analyze code patterns
- `POST /api/ml/deobfuscate/{id}` - Deobfuscate code using ML

## Architecture

The application is built using:
- **Backend**: Java with Javalin web framework
- **Analysis Engine**: Ghidra Headless Analyzer
- **ML Framework**: Deep Java Library (DJL) with PyTorch
- **Data Format**: JSON for API communication
- **Concurrency**: Asynchronous processing with CompletableFuture

## Scripts

The module includes specialized Ghidra scripts for malware analysis:

- `ExtractIOCs.java` - Comprehensive IOC extraction
- `ExtractMalwareFunctions.java` - Malware-specific function analysis
- Additional scripts for specific analysis workflows

## Configuration

Analysis options can be configured per request:

```json
{
  "analysisEnabled": true,
  "extractStrings": true,
  "extractFunctions": true,
  "extractIOCs": true,
  "performDeobfuscation": false,
  "useML": false,
  "timeoutSeconds": 3600
}
```

## Security Considerations

- File uploads are stored in temporary directories with cleanup
- Analysis is performed in isolated project environments
- API endpoints include basic input validation
- Consider running in containerized environments for additional isolation

## Contributing

This module is part of the Ghidra project. For contributions:
1. Follow Ghidra coding standards
2. Include appropriate tests
3. Update documentation as needed
4. Ensure compatibility with existing Ghidra infrastructure

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file in the Ghidra root directory.