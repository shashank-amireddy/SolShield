import { ToolResult, ToolMetadata } from '../types';
import { DeduplicatedVulnerability } from './VulnerabilityDeduplicator';
import { ToolConsensus } from './CrossToolAnalyzer';

export interface DashboardData {
  overview: OverviewData;
  toolBreakdown: ToolBreakdownData[];
  consensusView: ConsensusViewData;
  timeline: TimelineData[];
  detectionMatrix: DetectionMatrixData;
}

export interface OverviewData {
  totalTools: number;
  toolsRun: number;
  toolsSuccessful: number;
  detectionRatio: string; // e.g., "3/5 tools detected issues"
  overallRisk: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  consensusScore: number;
}

export interface ToolBreakdownData {
  toolName: string;
  version: string;
  status: 'success' | 'failed' | 'timeout' | 'not_run';
  executionTime: number;
  vulnerabilitiesFound: number;
  uniqueFindings: number;
  errors: string[];
  coverage: {
    filesAnalyzed: number;
    linesAnalyzed: number;
  };
}

export interface ConsensusViewData {
  unanimousFindings: number;
  majorityFindings: number;
  minorityFindings: number;
  singleToolFindings: number;
  disagreements: DisagreementData[];
}

export interface DisagreementData {
  vulnerability: DeduplicatedVulnerability;
  toolOpinions: {
    [toolName: string]: {
      detected: boolean;
      severity?: string;
      confidence?: number;
    };
  };
  explanation: string;
}

export interface TimelineData {
  timestamp: number;
  toolName: string;
  event: 'started' | 'completed' | 'failed';
  duration?: number;
  findingsCount?: number;
}

export interface DetectionMatrixData {
  vulnerabilityTypes: string[];
  tools: string[];
  matrix: boolean[][]; // matrix[toolIndex][vulnTypeIndex] = detected
  coverage: {
    [vulnType: string]: {
      detectedBy: string[];
      coverage: number; // percentage of tools that can detect this type
    };
  };
}

export class AnalysisDashboard {
  generateDashboard(
    toolResults: ToolResult[],
    toolMetadata: ToolMetadata[],
    deduplicatedVulnerabilities: DeduplicatedVulnerability[],
    toolConsensus: ToolConsensus[]
  ): DashboardData {
    return {
      overview: this.generateOverview(toolResults, toolMetadata, deduplicatedVulnerabilities),
      toolBreakdown: this.generateToolBreakdown(toolResults, toolMetadata),
      consensusView: this.generateConsensusView(toolConsensus),
      timeline: this.generateTimeline(toolResults),
      detectionMatrix: this.generateDetectionMatrix(deduplicatedVulnerabilities, toolMetadata)
    };
  }

  private generateOverview(
    toolResults: ToolResult[],
    toolMetadata: ToolMetadata[],
    vulnerabilities: DeduplicatedVulnerability[]
  ): OverviewData {
    const totalTools = toolMetadata.length;
    const toolsRun = toolResults.length;
    const toolsSuccessful = toolResults.filter(r => r.errors.length === 0).length;
    
    const toolsWithFindings = toolResults.filter(r => r.vulnerabilities.length > 0).length;
    const detectionRatio = `${toolsWithFindings}/${toolsRun} tools detected issues`;

    const overallRisk = this.calculateOverallRisk(vulnerabilities);
    const consensusScore = this.calculateOverallConsensusScore(vulnerabilities);

    return {
      totalTools,
      toolsRun,
      toolsSuccessful,
      detectionRatio,
      overallRisk,
      consensusScore
    };
  }

  private generateToolBreakdown(toolResults: ToolResult[], toolMetadata: ToolMetadata[]): ToolBreakdownData[] {
    const breakdown: ToolBreakdownData[] = [];

    for (const meta of toolMetadata) {
      const result = toolResults.find(r => r.toolName === meta.name);
      
      if (!result) {
        breakdown.push({
          toolName: meta.name,
          version: meta.version,
          status: 'not_run',
          executionTime: 0,
          vulnerabilitiesFound: 0,
          uniqueFindings: 0,
          errors: ['Tool was not executed'],
          coverage: { filesAnalyzed: 0, linesAnalyzed: 0 }
        });
        continue;
      }

      const status = this.determineToolStatus(result);
      const uniqueFindings = this.countUniqueFindings(result, toolResults);

      breakdown.push({
        toolName: result.toolName,
        version: result.toolVersion,
        status,
        executionTime: result.executionTime,
        vulnerabilitiesFound: result.vulnerabilities.length,
        uniqueFindings,
        errors: result.errors,
        coverage: {
          filesAnalyzed: result.metadata.filesProcessed || 0,
          linesAnalyzed: result.metadata.linesAnalyzed || 0
        }
      });
    }

    return breakdown;
  }

  private generateConsensusView(toolConsensus: ToolConsensus[]): ConsensusViewData {
    const unanimousFindings = toolConsensus.filter(c => c.agreementLevel === 'unanimous').length;
    const majorityFindings = toolConsensus.filter(c => c.agreementLevel === 'majority').length;
    const minorityFindings = toolConsensus.filter(c => c.agreementLevel === 'minority').length;
    const singleToolFindings = toolConsensus.filter(c => c.agreementLevel === 'single').length;

    const disagreements = this.findDisagreements(toolConsensus);

    return {
      unanimousFindings,
      majorityFindings,
      minorityFindings,
      singleToolFindings,
      disagreements
    };
  }

  private generateTimeline(toolResults: ToolResult[]): TimelineData[] {
    const timeline: TimelineData[] = [];
    let currentTime = Date.now() - toolResults.reduce((sum, r) => sum + r.executionTime, 0);

    for (const result of toolResults) {
      // Start event
      timeline.push({
        timestamp: currentTime,
        toolName: result.toolName,
        event: 'started'
      });

      // End event
      currentTime += result.executionTime;
      timeline.push({
        timestamp: currentTime,
        toolName: result.toolName,
        event: result.errors.length > 0 ? 'failed' : 'completed',
        duration: result.executionTime,
        findingsCount: result.vulnerabilities.length
      });
    }

    return timeline.sort((a, b) => a.timestamp - b.timestamp);
  }

  private generateDetectionMatrix(
    vulnerabilities: DeduplicatedVulnerability[],
    toolMetadata: ToolMetadata[]
  ): DetectionMatrixData {
    const vulnerabilityTypes = [...new Set(vulnerabilities.map(v => v.type))];
    const tools = toolMetadata.map(m => m.name);

    // Create detection matrix
    const matrix: boolean[][] = [];
    for (let toolIndex = 0; toolIndex < tools.length; toolIndex++) {
      matrix[toolIndex] = [];
      for (let vulnIndex = 0; vulnIndex < vulnerabilityTypes.length; vulnIndex++) {
        const vulnType = vulnerabilityTypes[vulnIndex];
        const toolName = tools[toolIndex];
        
        // Check if this tool detected any vulnerability of this type
        const detected = vulnerabilities.some(v => 
          v.type === vulnType && v.detectedByTools.includes(toolName)
        );
        
        matrix[toolIndex][vulnIndex] = detected;
      }
    }

    // Calculate coverage for each vulnerability type
    const coverage: DetectionMatrixData['coverage'] = {};
    for (const vulnType of vulnerabilityTypes) {
      const detectedBy = tools.filter(tool => 
        vulnerabilities.some(v => v.type === vulnType && v.detectedByTools.includes(tool))
      );
      
      coverage[vulnType] = {
        detectedBy,
        coverage: (detectedBy.length / tools.length) * 100
      };
    }

    return {
      vulnerabilityTypes,
      tools,
      matrix,
      coverage
    };
  }

  private calculateOverallRisk(vulnerabilities: DeduplicatedVulnerability[]): 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean' {
    if (vulnerabilities.length === 0) return 'Clean';

    const hasCritical = vulnerabilities.some(v => v.severity === 'Critical');
    const hasHigh = vulnerabilities.some(v => v.severity === 'High');
    const hasMedium = vulnerabilities.some(v => v.severity === 'Medium');

    if (hasCritical) return 'Critical';
    if (hasHigh) return 'High';
    if (hasMedium) return 'Medium';
    return 'Low';
  }

  private calculateOverallConsensusScore(vulnerabilities: DeduplicatedVulnerability[]): number {
    if (vulnerabilities.length === 0) return 1.0;

    const totalScore = vulnerabilities.reduce((sum, v) => sum + v.consensusScore, 0);
    return totalScore / vulnerabilities.length;
  }

  private determineToolStatus(result: ToolResult): 'success' | 'failed' | 'timeout' | 'not_run' {
    if (result.errors.length === 0) return 'success';
    
    const hasTimeoutError = result.errors.some(error => 
      error.toLowerCase().includes('timeout') || error.toLowerCase().includes('timed out')
    );
    
    return hasTimeoutError ? 'timeout' : 'failed';
  }

  private countUniqueFindings(targetResult: ToolResult, allResults: ToolResult[]): number {
    const otherResults = allResults.filter(r => r.toolName !== targetResult.toolName);
    
    let uniqueCount = 0;
    for (const vuln of targetResult.vulnerabilities) {
      const foundInOthers = otherResults.some(otherResult =>
        otherResult.vulnerabilities.some(otherVuln =>
          this.areSimilarVulnerabilities(vuln, otherVuln)
        )
      );
      
      if (!foundInOthers) {
        uniqueCount++;
      }
    }
    
    return uniqueCount;
  }

  private areSimilarVulnerabilities(vuln1: any, vuln2: any): boolean {
    return vuln1.type === vuln2.type && 
           vuln1.file === vuln2.file && 
           Math.abs(vuln1.lineNumber - vuln2.lineNumber) <= 5;
  }

  private findDisagreements(toolConsensus: ToolConsensus[]): DisagreementData[] {
    const disagreements: DisagreementData[] = [];

    for (const consensus of toolConsensus) {
      if (consensus.agreementLevel === 'minority' || consensus.agreementLevel === 'single') {
        const toolOpinions: DisagreementData['toolOpinions'] = {};
        
        for (const [toolName, agreement] of Object.entries(consensus.toolAgreement)) {
          toolOpinions[toolName] = {
            detected: agreement.detected,
            severity: agreement.detected ? agreement.severity : undefined,
            confidence: agreement.detected ? agreement.confidence : undefined
          };
        }

        disagreements.push({
          vulnerability: consensus.vulnerability,
          toolOpinions,
          explanation: this.generateDisagreementExplanation(consensus)
        });
      }
    }

    return disagreements;
  }

  private generateDisagreementExplanation(consensus: ToolConsensus): string {
    const detectedBy = consensus.vulnerability.detectedByTools;
    const totalTools = Object.keys(consensus.toolAgreement).length;
    
    if (consensus.agreementLevel === 'single') {
      return `Only ${detectedBy[0]} detected this vulnerability. This could indicate a tool-specific finding or a potential false positive that requires manual verification.`;
    } else {
      return `${detectedBy.length} out of ${totalTools} tools detected this vulnerability. The disagreement suggests this finding may require additional analysis or could be context-dependent.`;
    }
  }

  formatDashboardHtml(dashboard: DashboardData): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .dashboard { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 15px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .risk-clean { color: #6c757d; }
        .tool-status { display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }
        .status-success { background: #28a745; }
        .status-failed { background: #dc3545; }
        .status-timeout { background: #fd7e14; }
        .status-not_run { background: #6c757d; }
        .matrix { display: grid; gap: 2px; }
        .matrix-cell { padding: 8px; text-align: center; border-radius: 3px; }
        .matrix-detected { background: #28a745; color: white; }
        .matrix-not-detected { background: #e9ecef; }
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>🛡️ Security Analysis Dashboard</h1>
        
        <div class="card">
            <h2>Overview</h2>
            <div class="overview">
                <div class="metric">
                    <div class="metric-value">${dashboard.overview.detectionRatio}</div>
                    <div>Detection Ratio</div>
                </div>
                <div class="metric">
                    <div class="metric-value risk-${dashboard.overview.overallRisk.toLowerCase()}">${dashboard.overview.overallRisk}</div>
                    <div>Overall Risk</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${(dashboard.overview.consensusScore * 100).toFixed(1)}%</div>
                    <div>Consensus Score</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${dashboard.overview.toolsSuccessful}/${dashboard.overview.toolsRun}</div>
                    <div>Tools Successful</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Tool Breakdown</h2>
            ${dashboard.toolBreakdown.map(tool => `
                <div style="border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; border-radius: 5px;">
                    <h3>${tool.toolName} v${tool.version} 
                        <span class="tool-status status-${tool.status}">${tool.status.toUpperCase()}</span>
                    </h3>
                    <p>Execution Time: ${tool.executionTime}ms | Vulnerabilities: ${tool.vulnerabilitiesFound} | Unique: ${tool.uniqueFindings}</p>
                    ${tool.errors.length > 0 ? `<p style="color: #dc3545;">Errors: ${tool.errors.join(', ')}</p>` : ''}
                </div>
            `).join('')}
        </div>

        <div class="card">
            <h2>Consensus View</h2>
            <div class="overview">
                <div class="metric">
                    <div class="metric-value">${dashboard.consensusView.unanimousFindings}</div>
                    <div>Unanimous</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${dashboard.consensusView.majorityFindings}</div>
                    <div>Majority</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${dashboard.consensusView.minorityFindings}</div>
                    <div>Minority</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${dashboard.consensusView.singleToolFindings}</div>
                    <div>Single Tool</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Detection Matrix</h2>
            <p>Shows which tools can detect which vulnerability types:</p>
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr>
                            <th style="padding: 8px; border: 1px solid #dee2e6;">Tool</th>
                            ${dashboard.detectionMatrix.vulnerabilityTypes.map(type => 
                                `<th style="padding: 8px; border: 1px solid #dee2e6; writing-mode: vertical-rl;">${type}</th>`
                            ).join('')}
                        </tr>
                    </thead>
                    <tbody>
                        ${dashboard.detectionMatrix.tools.map((tool, toolIndex) => `
                            <tr>
                                <td style="padding: 8px; border: 1px solid #dee2e6; font-weight: bold;">${tool}</td>
                                ${dashboard.detectionMatrix.matrix[toolIndex].map(detected => 
                                    `<td class="matrix-cell ${detected ? 'matrix-detected' : 'matrix-not-detected'}" style="border: 1px solid #dee2e6;">
                                        ${detected ? '✓' : '✗'}
                                    </td>`
                                ).join('')}
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>`;
  }
}