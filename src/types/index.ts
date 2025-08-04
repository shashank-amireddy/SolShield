export interface RepositoryManager {
  cloneRepository(url: string): Promise<string>;
  findSolidityFiles(repoPath: string): Promise<string[]>;
  readFileContent(filePath: string): Promise<string>;
  cleanup(repoPath: string): Promise<void>;
}

export interface MultiToolRunner {
  registerTool(tool: SecurityTool): void;
  runAllTools(repoPath: string): Promise<ToolResult[]>;
  runSpecificTools(
    repoPath: string,
    toolNames: string[]
  ): Promise<ToolResult[]>;
  getAvailableTools(): SecurityTool[];
}

export interface SecurityTool {
  name: string;
  version: string;
  description: string;
  execute(repoPath: string, options?: ToolOptions): Promise<ToolResult>;
  parseOutput(rawOutput: string): Vulnerability[];
  isAvailable(): Promise<boolean>;
}

export interface ReportAggregator {
  deduplicateFindings(results: ToolResult[]): Promise<Vulnerability[]>;
  calculateConsensusScore(vulnerability: Vulnerability): number;
  generateReport(
    vulnerabilities: Vulnerability[],
    toolMetadata: ToolMetadata[]
  ): Promise<Report>;
  formatReport(report: Report, format: "json" | "html" | "markdown"): string;
}

export interface Vulnerability {
  type: VulnerabilityType;
  severity: "Critical" | "High" | "Medium" | "Low";
  file: string;
  lineNumber: number;
  codeSnippet: string;
  description: string;
  recommendation: string;
  toolSource: string;
  confidence: number;
}

export interface ToolResult {
  toolName: string;
  toolVersion: string;
  executionTime: number;
  vulnerabilities: Vulnerability[];
  errors: string[];
  metadata: Record<string, any>;
}

export interface Report {
  summary: ReportSummary;
  vulnerabilities: CategorizedVulnerabilities;
  risks: Risk[];
  recommendations: string[];
  metadata: ReportMetadata;
}

export interface ReportSummary {
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  toolsUsed: string[];
  analysisTime: number;
}

export interface CategorizedVulnerabilities {
  critical: Vulnerability[];
  high: Vulnerability[];
  medium: Vulnerability[];
  low: Vulnerability[];
}

export interface Risk {
  type: string;
  description: string;
  severity: "High" | "Medium" | "Low";
  recommendation: string;
}

export interface ReportMetadata {
  repositoryUrl: string;
  analysisDate: Date;
  toolVersions: Record<string, string>;
  filesAnalyzed: number;
}

export interface ToolMetadata {
  name: string;
  version: string;
  executionTime: number;
  filesProcessed: number;
}

export interface ToolOptions {
  timeout?: number;
  maxMemory?: string;
  additionalArgs?: string[];
}

export enum VulnerabilityType {
  REENTRANCY = "reentrancy",
  INTEGER_OVERFLOW = "integer_overflow",
  UNCHECKED_CALL = "unchecked_call",
  ACCESS_CONTROL = "access_control",
  TIMESTAMP_DEPENDENCE = "timestamp_dependence",
  DENIAL_OF_SERVICE = "denial_of_service",
  FRONT_RUNNING = "front_running",
  CROSS_CONTRACT_REENTRANCY = "cross_contract_reentrancy",
}
