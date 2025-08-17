import { ReportAggregator, ToolResult, Vulnerability, Report, ToolMetadata, ReportSummary, CategorizedVulnerabilities, Risk, ReportMetadata } from '../types';
import { VulnerabilityNormalizer, NormalizedVulnerability } from './VulnerabilityNormalizer';
import { VulnerabilityDeduplicator, DeduplicatedVulnerability } from './VulnerabilityDeduplicator';
import { CrossToolAnalyzer, CrossToolCorrelation, ToolConsensus } from './CrossToolAnalyzer';

export class VulnerabilityReportAggregator implements ReportAggregator {
  private normalizer: VulnerabilityNormalizer;
  private deduplicator: VulnerabilityDeduplicator;
  private crossToolAnalyzer: CrossToolAnalyzer;

  constructor() {
    this.normalizer = new VulnerabilityNormalizer();
    this.deduplicator = new VulnerabilityDeduplicator();
    this.crossToolAnalyzer = new CrossToolAnalyzer();
  }

  async deduplicateFindings(results: ToolResult[]): Promise<Vulnerability[]> {
    // Normalize vulnerabilities from all tools
    const normalizedVulnerabilities = this.normalizer.normalizeVulnerabilities(results);
    
    // Deduplicate similar findings
    const deduplicatedVulnerabilities = this.deduplicator.deduplicateVulnerabilities(normalizedVulnerabilities);
    
    // Convert back to base Vulnerability interface
    return deduplicatedVulnerabilities.map(vuln => ({
      type: vuln.type,
      severity: vuln.severity,
      file: vuln.file,
      lineNumber: vuln.lineNumber,
      codeSnippet: vuln.codeSnippet,
      description: vuln.description,
      recommendation: vuln.recommendation,
      toolSource: vuln.detectedByTools.join(', '),
      confidence: vuln.consensusScore
    }));
  }

  calculateConsensusScore(vulnerability: Vulnerability): number {
    // This is now handled by the deduplication process
    return vulnerability.confidence;
  }

  async generateReport(vulnerabilities: Vulnerability[], toolMetadata: ToolMetadata[]): Promise<Report> {
    // Re-normalize for internal processing
    const toolResults: ToolResult[] = toolMetadata.map(meta => ({
      toolName: meta.name,
      toolVersion: meta.version,
      executionTime: meta.executionTime,
      vulnerabilities: vulnerabilities.filter(v => v.toolSource.includes(meta.name)),
      errors: [],
      metadata: {}
    }));

    const normalizedVulnerabilities = this.normalizer.normalizeVulnerabilities(toolResults);
    const deduplicatedVulnerabilities = this.deduplicator.deduplicateVulnerabilities(normalizedVulnerabilities);
    
    // Perform cross-tool analysis
    const allToolNames = toolMetadata.map(meta => meta.name);
    const toolConsensus = this.crossToolAnalyzer.calculateToolConsensus(deduplicatedVulnerabilities, allToolNames);
    const correlations = this.crossToolAnalyzer.analyzeCorrelations(deduplicatedVulnerabilities);

    // Generate report components
    const summary = this.generateSummary(deduplicatedVulnerabilities, toolMetadata);
    const categorizedVulnerabilities = this.categorizeVulnerabilities(deduplicatedVulnerabilities);
    const risks = this.generateRisks(correlations, toolConsensus);
    const recommendations = this.generateRecommendations(deduplicatedVulnerabilities, correlations);
    const metadata = this.generateMetadata(toolMetadata, deduplicatedVulnerabilities.length);

    return {
      summary,
      vulnerabilities: categorizedVulnerabilities,
      risks,
      recommendations,
      metadata
    };
  }

  formatReport(report: Report, format: 'json' | 'html' | 'markdown'): string {
    switch (format) {
      case 'json':
        return JSON.stringify(report, null, 2);
      case 'html':
        return this.formatHtmlReport(report);
      case 'markdown':
        return this.formatMarkdownReport(report);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  private generateSummary(vulnerabilities: DeduplicatedVulnerability[], toolMetadata: ToolMetadata[]): ReportSummary {
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    for (const vuln of vulnerabilities) {
      switch (vuln.severity) {
        case 'Critical':
          severityCounts.critical++;
          break;
        case 'High':
          severityCounts.high++;
          break;
        case 'Medium':
          severityCounts.medium++;
          break;
        case 'Low':
          severityCounts.low++;
          break;
      }
    }

    const totalAnalysisTime = toolMetadata.reduce((sum, meta) => sum + meta.executionTime, 0);
    const toolsUsed = toolMetadata.map(meta => `${meta.name} v${meta.version}`);

    return {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: severityCounts.critical,
      highCount: severityCounts.high,
      mediumCount: severityCounts.medium,
      lowCount: severityCounts.low,
      toolsUsed,
      analysisTime: totalAnalysisTime
    };
  }

  private categorizeVulnerabilities(vulnerabilities: DeduplicatedVulnerability[]): CategorizedVulnerabilities {
    const categorized: CategorizedVulnerabilities = {
      critical: [],
      high: [],
      medium: [],
      low: []
    };

    for (const vuln of vulnerabilities) {
      const baseVuln: Vulnerability = {
        type: vuln.type,
        severity: vuln.severity,
        file: vuln.file,
        lineNumber: vuln.lineNumber,
        codeSnippet: vuln.codeSnippet,
        description: vuln.description,
        recommendation: vuln.recommendation,
        toolSource: vuln.detectedByTools.join(', '),
        confidence: vuln.consensusScore
      };

      switch (vuln.severity) {
        case 'Critical':
          categorized.critical.push(baseVuln);
          break;
        case 'High':
          categorized.high.push(baseVuln);
          break;
        case 'Medium':
          categorized.medium.push(baseVuln);
          break;
        case 'Low':
          categorized.low.push(baseVuln);
          break;
      }
    }

    return categorized;
  }

  private generateRisks(correlations: CrossToolCorrelation[], consensus: ToolConsensus[]): Risk[] {
    const risks: Risk[] = [];

    // Add correlation-based risks
    for (const correlation of correlations) {
      risks.push({
        type: `${correlation.correlationType}_vulnerability_chain`,
        description: correlation.description,
        severity: correlation.riskAmplification > 80 ? 'High' : correlation.riskAmplification > 50 ? 'Medium' : 'Low',
        recommendation: correlation.recommendation
      });
    }

    // Add consensus-based risks
    const lowConsensusVulns = consensus.filter(c => c.agreementLevel === 'single' && c.vulnerability.severity === 'Critical');
    if (lowConsensusVulns.length > 0) {
      risks.push({
        type: 'low_consensus_critical',
        description: `${lowConsensusVulns.length} critical vulnerabilities detected by only one tool. These may be false positives or tool-specific findings that require manual verification.`,
        severity: 'Medium',
        recommendation: 'Manually review these findings and consider running additional analysis tools for verification.'
      });
    }

    return risks;
  }

  private generateRecommendations(vulnerabilities: DeduplicatedVulnerability[], correlations: CrossToolCorrelation[]): string[] {
    const recommendations: string[] = [];

    // Priority recommendations based on severity
    const criticalCount = vulnerabilities.filter(v => v.severity === 'Critical').length;
    if (criticalCount > 0) {
      recommendations.push(`Immediately address ${criticalCount} critical vulnerabilities before deployment.`);
    }

    // Multi-tool consensus recommendations
    const consensusVulns = vulnerabilities.filter(v => v.detectedByTools.length > 1);
    if (consensusVulns.length > 0) {
      recommendations.push(`${consensusVulns.length} vulnerabilities were detected by multiple tools, indicating high confidence findings.`);
    }

    // Correlation-based recommendations
    if (correlations.length > 0) {
      recommendations.push(`${correlations.length} vulnerability correlations detected. Address primary vulnerabilities to break attack chains.`);
    }

    // General security recommendations
    recommendations.push('Implement comprehensive unit tests covering security scenarios.');
    recommendations.push('Consider formal verification for critical contract functions.');
    recommendations.push('Establish a regular security audit schedule.');

    return recommendations;
  }

  private generateMetadata(toolMetadata: ToolMetadata[], vulnerabilityCount: number): ReportMetadata {
    const toolVersions: Record<string, string> = {};
    for (const meta of toolMetadata) {
      toolVersions[meta.name] = meta.version;
    }

    return {
      repositoryUrl: '', // Will be set by the caller
      analysisDate: new Date(),
      toolVersions,
      filesAnalyzed: vulnerabilityCount // Approximation
    };
  }

  private formatHtmlReport(report: Report): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>SolShield Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .code { background: #f8f8f8; padding: 10px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Solidity Security Analysis Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Vulnerabilities: ${report.summary.totalVulnerabilities}</p>
        <p>Critical: ${report.summary.criticalCount}, High: ${report.summary.highCount}, Medium: ${report.summary.mediumCount}, Low: ${report.summary.lowCount}</p>
        <p>Analysis Time: ${report.summary.analysisTime}ms</p>
        <p>Tools Used: ${report.summary.toolsUsed.join(', ')}</p>
    </div>

    <h2>Critical Vulnerabilities</h2>
    ${report.vulnerabilities.critical.map(v => this.formatHtmlVulnerability(v, 'critical')).join('')}

    <h2>High Severity Vulnerabilities</h2>
    ${report.vulnerabilities.high.map(v => this.formatHtmlVulnerability(v, 'high')).join('')}

    <h2>Medium Severity Vulnerabilities</h2>
    ${report.vulnerabilities.medium.map(v => this.formatHtmlVulnerability(v, 'medium')).join('')}

    <h2>Low Severity Vulnerabilities</h2>
    ${report.vulnerabilities.low.map(v => this.formatHtmlVulnerability(v, 'low')).join('')}

    <h2>Recommendations</h2>
    <ul>
        ${report.recommendations.map(rec => `<li>${rec}</li>`).join('')}
    </ul>
</body>
</html>`;
  }

  private formatHtmlVulnerability(vuln: Vulnerability, severity: string): string {
    return `
    <div class="vulnerability ${severity}">
        <h3>${vuln.type} - ${vuln.file}:${vuln.lineNumber}</h3>
        <p><strong>Description:</strong> ${vuln.description}</p>
        <p><strong>Code:</strong></p>
        <div class="code">${vuln.codeSnippet}</div>
        <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
        <p><strong>Detected by:</strong> ${vuln.toolSource} (Confidence: ${(vuln.confidence * 100).toFixed(1)}%)</p>
    </div>`;
  }

  private formatMarkdownReport(report: Report): string {
    return `# Solidity Security Analysis Report

## Summary

- **Total Vulnerabilities:** ${report.summary.totalVulnerabilities}
- **Critical:** ${report.summary.criticalCount}
- **High:** ${report.summary.highCount}
- **Medium:** ${report.summary.mediumCount}
- **Low:** ${report.summary.lowCount}
- **Analysis Time:** ${report.summary.analysisTime}ms
- **Tools Used:** ${report.summary.toolsUsed.join(', ')}

## Critical Vulnerabilities

${report.vulnerabilities.critical.map(v => this.formatMarkdownVulnerability(v)).join('\n')}

## High Severity Vulnerabilities

${report.vulnerabilities.high.map(v => this.formatMarkdownVulnerability(v)).join('\n')}

## Medium Severity Vulnerabilities

${report.vulnerabilities.medium.map(v => this.formatMarkdownVulnerability(v)).join('\n')}

## Low Severity Vulnerabilities

${report.vulnerabilities.low.map(v => this.formatMarkdownVulnerability(v)).join('\n')}

## Recommendations

${report.recommendations.map(rec => `- ${rec}`).join('\n')}

## Analysis Metadata

- **Analysis Date:** ${report.metadata.analysisDate.toISOString()}
- **Files Analyzed:** ${report.metadata.filesAnalyzed}
- **Tool Versions:** ${Object.entries(report.metadata.toolVersions).map(([name, version]) => `${name} v${version}`).join(', ')}
`;
  }

  private formatMarkdownVulnerability(vuln: Vulnerability): string {
    return `
### ${vuln.type} - \`${vuln.file}:${vuln.lineNumber}\`

**Description:** ${vuln.description}

**Code:**
\`\`\`solidity
${vuln.codeSnippet}
\`\`\`

**Recommendation:** ${vuln.recommendation}

**Detected by:** ${vuln.toolSource} (Confidence: ${(vuln.confidence * 100).toFixed(1)}%)

---
`;
  }
}