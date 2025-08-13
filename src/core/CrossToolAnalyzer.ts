import { DeduplicatedVulnerability } from './VulnerabilityDeduplicator';
import { VulnerabilityType } from '../types';

export interface CrossToolCorrelation {
  primaryVulnerability: DeduplicatedVulnerability;
  relatedVulnerabilities: DeduplicatedVulnerability[];
  correlationType: 'chain' | 'compound' | 'context';
  riskAmplification: number;
  description: string;
  recommendation: string;
}

export interface ToolConsensus {
  vulnerability: DeduplicatedVulnerability;
  agreementLevel: 'unanimous' | 'majority' | 'minority' | 'single';
  toolAgreement: {
    [toolName: string]: {
      detected: boolean;
      confidence: number;
      severity: string;
    };
  };
  consensusConfidence: number;
}

export class CrossToolAnalyzer {
  private vulnerabilityChains: Map<VulnerabilityType, VulnerabilityType[]>;

  constructor() {
    this.vulnerabilityChains = this.initializeVulnerabilityChains();
  }

  analyzeCorrelations(vulnerabilities: DeduplicatedVulnerability[]): CrossToolCorrelation[] {
    const correlations: CrossToolCorrelation[] = [];

    // Find vulnerability chains
    correlations.push(...this.findVulnerabilityChains(vulnerabilities));

    // Find compound vulnerabilities (multiple issues in same function/contract)
    correlations.push(...this.findCompoundVulnerabilities(vulnerabilities));

    // Find contextual relationships
    correlations.push(...this.findContextualRelationships(vulnerabilities));

    return correlations;
  }

  calculateToolConsensus(vulnerabilities: DeduplicatedVulnerability[], allToolNames: string[]): ToolConsensus[] {
    return vulnerabilities.map(vuln => {
      const toolAgreement: ToolConsensus['toolAgreement'] = {};
      
      // Initialize all tools as not detected
      for (const toolName of allToolNames) {
        toolAgreement[toolName] = {
          detected: false,
          confidence: 0,
          severity: 'Low'
        };
      }

      // Mark tools that detected this vulnerability
      for (const toolName of vuln.detectedByTools) {
        toolAgreement[toolName] = {
          detected: true,
          confidence: vuln.confidence,
          severity: vuln.severity
        };
      }

      const detectionCount = vuln.detectedByTools.length;
      const totalTools = allToolNames.length;
      const agreementRatio = detectionCount / totalTools;

      let agreementLevel: ToolConsensus['agreementLevel'];
      if (agreementRatio === 1) {
        agreementLevel = 'unanimous';
      } else if (agreementRatio >= 0.5) {
        agreementLevel = 'majority';
      } else if (agreementRatio > 1 / totalTools) {
        agreementLevel = 'minority';
      } else {
        agreementLevel = 'single';
      }

      // Calculate consensus confidence based on agreement level and individual confidences
      const consensusConfidence = this.calculateConsensusConfidence(
        vuln.confidence,
        agreementRatio,
        vuln.detectedByTools.length
      );

      return {
        vulnerability: vuln,
        agreementLevel,
        toolAgreement,
        consensusConfidence
      };
    });
  }

  private initializeVulnerabilityChains(): Map<VulnerabilityType, VulnerabilityType[]> {
    const chains = new Map<VulnerabilityType, VulnerabilityType[]>();

    // Reentrancy can lead to other issues
    chains.set(VulnerabilityType.REENTRANCY, [
      VulnerabilityType.UNCHECKED_CALL,
      VulnerabilityType.ACCESS_CONTROL
    ]);

    // Access control issues can enable other attacks
    chains.set(VulnerabilityType.ACCESS_CONTROL, [
      VulnerabilityType.REENTRANCY,
      VulnerabilityType.INTEGER_OVERFLOW,
      VulnerabilityType.UNCHECKED_CALL
    ]);

    // Unchecked calls can lead to reentrancy
    chains.set(VulnerabilityType.UNCHECKED_CALL, [
      VulnerabilityType.REENTRANCY,
      VulnerabilityType.DENIAL_OF_SERVICE
    ]);

    // Integer overflow can be exploited with other vulnerabilities
    chains.set(VulnerabilityType.INTEGER_OVERFLOW, [
      VulnerabilityType.ACCESS_CONTROL,
      VulnerabilityType.REENTRANCY
    ]);

    // Front-running can amplify other issues
    chains.set(VulnerabilityType.FRONT_RUNNING, [
      VulnerabilityType.ACCESS_CONTROL,
      VulnerabilityType.TIMESTAMP_DEPENDENCE
    ]);

    return chains;
  }

  private findVulnerabilityChains(vulnerabilities: DeduplicatedVulnerability[]): CrossToolCorrelation[] {
    const correlations: CrossToolCorrelation[] = [];
    const vulnerabilityMap = new Map<string, DeduplicatedVulnerability[]>();

    // Group vulnerabilities by file
    for (const vuln of vulnerabilities) {
      const key = vuln.file;
      if (!vulnerabilityMap.has(key)) {
        vulnerabilityMap.set(key, []);
      }
      vulnerabilityMap.get(key)!.push(vuln);
    }

    // Look for chains within each file
    for (const [file, fileVulns] of vulnerabilityMap) {
      for (const primaryVuln of fileVulns) {
        const chainTypes = this.vulnerabilityChains.get(primaryVuln.type);
        if (!chainTypes) continue;

        const relatedVulns = fileVulns.filter(v => 
          v !== primaryVuln && 
          chainTypes.includes(v.type) &&
          Math.abs(v.lineNumber - primaryVuln.lineNumber) <= 50 // Within 50 lines
        );

        if (relatedVulns.length > 0) {
          correlations.push({
            primaryVulnerability: primaryVuln,
            relatedVulnerabilities: relatedVulns,
            correlationType: 'chain',
            riskAmplification: this.calculateChainRiskAmplification(primaryVuln, relatedVulns),
            description: this.generateChainDescription(primaryVuln, relatedVulns),
            recommendation: this.generateChainRecommendation(primaryVuln, relatedVulns)
          });
        }
      }
    }

    return correlations;
  }

  private findCompoundVulnerabilities(vulnerabilities: DeduplicatedVulnerability[]): CrossToolCorrelation[] {
    const correlations: CrossToolCorrelation[] = [];
    const functionMap = new Map<string, DeduplicatedVulnerability[]>();

    // Group vulnerabilities by function (approximate by line proximity)
    for (const vuln of vulnerabilities) {
      const functionKey = `${vuln.file}:${Math.floor(vuln.lineNumber / 20)}`; // Group by 20-line blocks
      if (!functionMap.has(functionKey)) {
        functionMap.set(functionKey, []);
      }
      functionMap.get(functionKey)!.push(vuln);
    }

    // Find functions with multiple vulnerabilities
    for (const [functionKey, functionVulns] of functionMap) {
      if (functionVulns.length > 1) {
        const primaryVuln = functionVulns.reduce((prev, current) => 
          current.normalizedSeverity > prev.normalizedSeverity ? current : prev
        );
        const relatedVulns = functionVulns.filter(v => v !== primaryVuln);

        correlations.push({
          primaryVulnerability: primaryVuln,
          relatedVulnerabilities: relatedVulns,
          correlationType: 'compound',
          riskAmplification: this.calculateCompoundRiskAmplification(functionVulns),
          description: this.generateCompoundDescription(functionVulns),
          recommendation: this.generateCompoundRecommendation(functionVulns)
        });
      }
    }

    return correlations;
  }

  private findContextualRelationships(vulnerabilities: DeduplicatedVulnerability[]): CrossToolCorrelation[] {
    const correlations: CrossToolCorrelation[] = [];
    
    // Find vulnerabilities that share similar contexts (same contract, similar patterns)
    const contextGroups = this.groupByContext(vulnerabilities);
    
    for (const group of contextGroups) {
      if (group.length > 1) {
        const primaryVuln = group.reduce((prev, current) => 
          current.consensusScore > prev.consensusScore ? current : prev
        );
        const relatedVulns = group.filter(v => v !== primaryVuln);

        correlations.push({
          primaryVulnerability: primaryVuln,
          relatedVulnerabilities: relatedVulns,
          correlationType: 'context',
          riskAmplification: this.calculateContextRiskAmplification(group),
          description: this.generateContextDescription(group),
          recommendation: this.generateContextRecommendation(group)
        });
      }
    }

    return correlations;
  }

  private groupByContext(vulnerabilities: DeduplicatedVulnerability[]): DeduplicatedVulnerability[][] {
    const groups: DeduplicatedVulnerability[][] = [];
    const processed = new Set<DeduplicatedVulnerability>();

    for (const vuln of vulnerabilities) {
      if (processed.has(vuln)) continue;

      const contextGroup = [vuln];
      processed.add(vuln);

      // Find vulnerabilities with similar context
      for (const otherVuln of vulnerabilities) {
        if (processed.has(otherVuln)) continue;

        if (this.haveSimilarContext(vuln, otherVuln)) {
          contextGroup.push(otherVuln);
          processed.add(otherVuln);
        }
      }

      if (contextGroup.length > 1) {
        groups.push(contextGroup);
      }
    }

    return groups;
  }

  private haveSimilarContext(vuln1: DeduplicatedVulnerability, vuln2: DeduplicatedVulnerability): boolean {
    // Same file and similar descriptions suggest similar context
    if (vuln1.file !== vuln2.file) return false;

    // Check if descriptions have common keywords
    const keywords1 = new Set(vuln1.description.toLowerCase().split(/\s+/));
    const keywords2 = new Set(vuln2.description.toLowerCase().split(/\s+/));
    const commonKeywords = new Set([...keywords1].filter(k => keywords2.has(k)));
    
    return commonKeywords.size >= 3; // At least 3 common keywords
  }

  private calculateChainRiskAmplification(primary: DeduplicatedVulnerability, related: DeduplicatedVulnerability[]): number {
    const baseRisk = primary.normalizedSeverity;
    const chainMultiplier = 1 + (related.length * 0.2); // 20% increase per related vulnerability
    return Math.min(baseRisk * chainMultiplier, 100);
  }

  private calculateCompoundRiskAmplification(vulnerabilities: DeduplicatedVulnerability[]): number {
    const maxSeverity = Math.max(...vulnerabilities.map(v => v.normalizedSeverity));
    const compoundMultiplier = 1 + ((vulnerabilities.length - 1) * 0.15); // 15% increase per additional vulnerability
    return Math.min(maxSeverity * compoundMultiplier, 100);
  }

  private calculateContextRiskAmplification(vulnerabilities: DeduplicatedVulnerability[]): number {
    const avgSeverity = vulnerabilities.reduce((sum, v) => sum + v.normalizedSeverity, 0) / vulnerabilities.length;
    const contextMultiplier = 1 + (vulnerabilities.length * 0.1); // 10% increase per contextual vulnerability
    return Math.min(avgSeverity * contextMultiplier, 100);
  }

  private calculateConsensusConfidence(baseConfidence: number, agreementRatio: number, toolCount: number): number {
    // Base confidence weighted by agreement ratio and tool count
    const agreementBonus = agreementRatio * 0.3; // Up to 30% bonus for full agreement
    const toolCountBonus = Math.min(toolCount * 0.05, 0.2); // Up to 20% bonus for multiple tools
    
    return Math.min(baseConfidence + agreementBonus + toolCountBonus, 1.0);
  }

  private generateChainDescription(primary: DeduplicatedVulnerability, related: DeduplicatedVulnerability[]): string {
    const relatedTypes = related.map(v => v.type).join(', ');
    return `Vulnerability chain detected: ${primary.type} can enable ${relatedTypes}. This creates a compound security risk where the primary vulnerability can be exploited to trigger additional attack vectors.`;
  }

  private generateCompoundDescription(vulnerabilities: DeduplicatedVulnerability[]): string {
    const types = vulnerabilities.map(v => v.type).join(', ');
    return `Multiple vulnerabilities detected in the same function/area: ${types}. These issues compound each other and significantly increase the attack surface.`;
  }

  private generateContextDescription(vulnerabilities: DeduplicatedVulnerability[]): string {
    const types = [...new Set(vulnerabilities.map(v => v.type))].join(', ');
    return `Related vulnerabilities with similar context: ${types}. These issues share common patterns and may indicate systemic security problems.`;
  }

  private generateChainRecommendation(primary: DeduplicatedVulnerability, related: DeduplicatedVulnerability[]): string {
    return `Address the primary vulnerability (${primary.type}) first, as it enables the related issues. Implement comprehensive security measures to break the vulnerability chain and prevent cascading attacks.`;
  }

  private generateCompoundRecommendation(vulnerabilities: DeduplicatedVulnerability[]): string {
    return `Refactor the affected function/area to address all identified vulnerabilities simultaneously. Consider breaking down complex functions and implementing defense-in-depth strategies.`;
  }

  private generateContextRecommendation(vulnerabilities: DeduplicatedVulnerability[]): string {
    return `Review the overall security architecture and coding patterns. These related vulnerabilities suggest the need for systematic security improvements and better development practices.`;
  }
}