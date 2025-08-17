# 🛡️ SolShield

A comprehensive security analysis platform for Solidity smart contracts that integrates multiple security analysis tools to provide thorough vulnerability detection with VirusTotal-style consensus reporting.

## ✨ Features

### 🔍 Multi-Tool Analysis

- **Slither**: Fast static analysis for common vulnerabilities
- **Mythril**: Symbolic execution for deep security analysis
- **SmartCheck**: Pattern-based vulnerability detection
- **Solhint**: Code quality and security linting
- **Securify2**: Formal verification for critical functions

### 🎯 Advanced Analysis

- **Intelligent Deduplication**: Eliminates duplicate findings across tools
- **Cross-Tool Correlation**: Identifies vulnerability chains and compound risks
- **Consensus Scoring**: VirusTotal-style detection ratios (e.g., "3/5 tools detected")
- **Risk Amplification**: Calculates compound risk from related vulnerabilities

### 📊 Comprehensive Reporting

- **Multiple Formats**: JSON, HTML, Markdown, and interactive dashboard
- **Tool Attribution**: Shows which tools detected each vulnerability
- **Executive Summary**: High-level overview for stakeholders
- **Detailed Analysis**: Technical details for developers

### 🚀 Developer Experience

- **GitHub Integration**: Analyze repositories directly from URLs
- **CLI Interface**: Simple command-line interface with rich output
- **Docker Support**: Containerized execution with all tools pre-installed
- **Configurable**: Flexible tool selection and timeout settings

## 📦 Installation

### Prerequisites

- Node.js 18+
- Python 3.8+ (for security tools)
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/SolShield
cd SolShield

# Install dependencies
npm install

# Build the project
npm run build

# Install security analysis tools (optional - Docker includes them)
pip install slither-analyzer mythril
```

### Docker Installation (Recommended)

```bash
# Build Docker image with all tools pre-installed
docker build -t solidity-scanner .

# Or pull from registry
docker pull your-org/solidity-scanner
```

## 🚀 Usage

### Basic Scanning

```bash
# Scan a public GitHub repository
npm run dev scan https://github.com/OpenZeppelin/openzeppelin-contracts

# Scan with specific output format
npm run dev scan https://github.com/user/repo --output html

# Generate interactive dashboard
npm run dev scan https://github.com/user/repo --output dashboard
```

### Advanced Options

```bash
# Use specific tools only
npm run dev scan https://github.com/user/repo --tools slither,mythril

# Set custom timeout (in milliseconds)
npm run dev scan https://github.com/user/repo --timeout 600000

# Scan private repository with token
npm run dev scan https://github.com/user/private-repo --token ghp_your_token

# Save report to specific file
npm run dev scan https://github.com/user/repo --file security-report.html

# Enable verbose logging
npm run dev scan https://github.com/user/repo --verbose
```

### Docker Usage

```bash
# Basic scan with Docker
docker run -it solidity-scanner scan https://github.com/user/repo

# Mount volume for report output
docker run -v $(pwd):/output solidity-scanner scan https://github.com/user/repo --file /output/report.html

# Pass GitHub token via environment variable
docker run -e GITHUB_TOKEN=ghp_your_token solidity-scanner scan https://github.com/user/private-repo
```

### List Available Tools

```bash
# Check which tools are available and properly installed
npm run dev list-tools
```

## 📊 Report Formats

### JSON Report

```json
{
  "summary": {
    "totalVulnerabilities": 15,
    "criticalCount": 2,
    "highCount": 5,
    "mediumCount": 6,
    "lowCount": 2,
    "toolsUsed": ["Slither v0.9.6", "Mythril v0.23.0"],
    "analysisTime": 45000
  },
  "vulnerabilities": {
    "critical": [...],
    "high": [...],
    "medium": [...],
    "low": [...]
  },
  "risks": [...],
  "recommendations": [...]
}
```

### Interactive Dashboard

The dashboard provides a VirusTotal-style interface showing:

- **Detection Ratios**: "3/5 tools detected issues"
- **Tool Breakdown**: Individual tool results and performance
- **Consensus View**: Agreement levels between tools
- **Detection Matrix**: Which tools detect which vulnerability types

### HTML Report

Formatted HTML report with:

- Executive summary with key metrics
- Categorized vulnerabilities by severity
- Code snippets and recommendations
- Tool attribution and confidence scores

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │    │  Web Interface  │    │   API Gateway   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Analysis Engine │
                    │  Orchestrator   │
                    └─────────┬───────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
┌─────────▼───────┐  ┌────────▼────────┐  ┌──────▼──────┐
│ Repository      │  │ Multi-Tool      │  │ Report      │
│ Manager         │  │ Runner          │  │ Aggregator  │
└─────────────────┘  └────────┬────────┘  └─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼───────┐  ┌──────────▼──────────┐  ┌───────▼───────┐
│    Slither    │  │      Mythril        │  │  SmartCheck   │
│ (Fast Static) │  │ (Symbolic Exec)     │  │(Pattern-Based)│
└───────────────┘  └─────────────────────┘  └───────────────┘
```

### Analysis Pipeline

1. **Repository Access**: Clone GitHub repository and discover Solidity files
2. **Tool Execution**: Run multiple security analysis tools in parallel
3. **Normalization**: Convert tool outputs to unified vulnerability format
4. **Deduplication**: Identify and merge duplicate findings
5. **Correlation**: Analyze relationships between vulnerabilities
6. **Report Generation**: Create comprehensive reports in multiple formats

## 🔧 Configuration

### Environment Variables

```bash
# GitHub token for private repositories
export GITHUB_TOKEN=ghp_your_token_here

# Custom temporary directory
export SCANNER_TEMP_DIR=/custom/temp/path

# Default timeout in milliseconds
export SCANNER_TIMEOUT=300000

# Maximum retry attempts
export SCANNER_MAX_RETRIES=3
```

### Tool Configuration

Each security tool can be configured individually:

```typescript
// Custom tool timeout
npm run dev scan repo --timeout 600000

// Tool-specific arguments
npm run dev scan repo --tools slither --args "--exclude-dependencies"
```

## 🧪 Development

### Setup Development Environment

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint

# Fix linting issues
npm run lint:fix
```

### Project Structure

```
src/
├── core/                 # Core analysis components
│   ├── RepositoryManager.ts
│   ├── MultiToolRunner.ts
│   ├── ReportAggregator.ts
│   ├── VulnerabilityNormalizer.ts
│   ├── VulnerabilityDeduplicator.ts
│   ├── CrossToolAnalyzer.ts
│   └── AnalysisDashboard.ts
├── tools/               # Security tool integrations
│   ├── SlitherTool.ts
│   ├── MythrilTool.ts
│   ├── SmartCheckTool.ts
│   ├── SolhintTool.ts
│   └── Securify2Tool.ts
├── utils/               # Utility functions
│   ├── config.ts
│   ├── errorHandler.ts
│   ├── fileSystem.ts
│   └── process.ts
├── types/               # TypeScript type definitions
└── __tests__/           # Test files
    ├── unit/
    └── integration/
```

### Adding New Security Tools

1. **Create Tool Implementation**:

```typescript
// src/tools/NewTool.ts
import { BaseSecurityTool } from "./base/SecurityTool";

export class NewTool extends BaseSecurityTool {
  name = "NewTool";
  version = "1.0.0";
  description = "Description of the new tool";

  async execute(repoPath: string, options?: ToolOptions): Promise<ToolResult> {
    // Implementation
  }

  async isAvailable(): Promise<boolean> {
    // Check if tool is installed
  }

  parseOutput(rawOutput: string): Vulnerability[] {
    // Parse tool output
  }
}
```

2. **Register in Tool Registry**:

```typescript
// src/core/ToolRegistry.ts
this.availableToolClasses.set("newtool", NewTool);
```

3. **Add Tests**:

```typescript
// src/__tests__/NewTool.test.ts
describe("NewTool", () => {
  // Unit tests
});
```

## 🐳 Docker

### Building Custom Images

```dockerfile
# Dockerfile.custom
FROM node:18-alpine

# Install additional security tools
RUN apk add --no-cache your-tool

# Copy and build application
COPY . /app
WORKDIR /app
RUN npm ci && npm run build

ENTRYPOINT ["node", "dist/index.js"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: "3.8"
services:
  scanner:
    build: .
    volumes:
      - ./reports:/app/reports
    environment:
      - GITHUB_TOKEN=${GITHUB_TOKEN}
    command: scan https://github.com/user/repo --file /app/reports/report.html
```

## 📈 Performance

### Benchmarks

- **Small Repository** (< 10 files): ~30 seconds
- **Medium Repository** (10-50 files): ~2-5 minutes
- **Large Repository** (50+ files): ~5-15 minutes

### Optimization Tips

- Use `--tools` to run only necessary tools
- Set appropriate `--timeout` values
- Use Docker for consistent performance
- Enable `--verbose` for debugging slow scans

## 🤝 Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and add tests
4. Run tests: `npm test`
5. Lint code: `npm run lint`
6. Commit changes: `git commit -m "Add new feature"`
7. Push to branch: `git push origin feature/new-feature`
8. Create Pull Request

### Code Standards

- TypeScript with strict mode
- ESLint for code quality
- Jest for testing
- Conventional commits
- 100% test coverage for new features

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Slither](https://github.com/crytic/slither) - Static analysis framework
- [Mythril](https://github.com/ConsenSys/mythril) - Security analysis tool
- [SmartCheck](https://github.com/smartdec/smartcheck) - Static analysis tool
- [Solhint](https://github.com/protofire/solhint) - Solidity linter
- [Securify](https://github.com/eth-sri/securify2) - Formal verification

## 📞 Support

- 📧 Email: hello@quantumloom.in
- 🐛 Issues: [GitHub Issues](https://github.com/shashank-amireddy/SolShield/issues)
- 📖 Documentation: Coming Soon
