export interface ScannerConfig {
  githubToken?: string;
  tempDir?: string;
  timeout?: number;
  maxRetries?: number;
}

export class ConfigManager {
  private static instance: ConfigManager;
  private config: ScannerConfig = {};

  private constructor() {
    this.loadFromEnvironment();
  }

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  private loadFromEnvironment(): void {
    this.config = {
      githubToken: process.env.GITHUB_TOKEN,
      tempDir: process.env.SCANNER_TEMP_DIR,
      timeout: process.env.SCANNER_TIMEOUT ? parseInt(process.env.SCANNER_TIMEOUT) : 300000, // 5 minutes default
      maxRetries: process.env.SCANNER_MAX_RETRIES ? parseInt(process.env.SCANNER_MAX_RETRIES) : 3
    };
  }

  getConfig(): ScannerConfig {
    return { ...this.config };
  }

  setConfig(config: Partial<ScannerConfig>): void {
    this.config = { ...this.config, ...config };
  }

  getGitHubToken(): string | undefined {
    return this.config.githubToken;
  }

  getTempDir(): string | undefined {
    return this.config.tempDir;
  }

  getTimeout(): number {
    return this.config.timeout || 300000;
  }

  getMaxRetries(): number {
    return this.config.maxRetries || 3;
  }
}