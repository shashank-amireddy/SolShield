import { RepositoryManager } from '../types';
import simpleGit, { SimpleGit } from 'simple-git';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';
import { ConfigManager } from '../utils/config';

export class GitHubRepositoryManager implements RepositoryManager {
  private git: SimpleGit;
  private tempDir: string;
  private configManager: ConfigManager;

  constructor() {
    this.git = simpleGit();
    this.configManager = ConfigManager.getInstance();
    this.tempDir = this.configManager.getTempDir() || path.join(os.tmpdir(), 'solidity-scanner');
  }

  async cloneRepository(url: string): Promise<string> {
    // Validate GitHub URL format
    if (!this.isValidGitHubUrl(url)) {
      throw new Error(`Invalid GitHub URL format: ${url}`);
    }

    // Create unique temporary directory for this repository
    const repoName = this.extractRepoName(url);
    const timestamp = Date.now();
    const repoPath = path.join(this.tempDir, `${repoName}-${timestamp}`);

    try {
      // Ensure temp directory exists
      await fs.ensureDir(this.tempDir);

      // Prepare clone URL with authentication if token is available
      const cloneUrl = this.prepareCloneUrl(url);
      
      // Clone options
      const cloneOptions: Record<string, any> = {
        '--depth': 1, // Shallow clone for faster download
        '--single-branch': null
      };

      // Add timeout if configured
      const timeout = this.configManager.getTimeout();
      if (timeout > 0) {
        cloneOptions['--config'] = `http.timeout=${Math.floor(timeout / 1000)}`;
      }

      // Clone the repository with retry logic
      console.log(`Cloning repository: ${url}`);
      await this.retryOperation(
        () => this.git.clone(cloneUrl, repoPath, cloneOptions),
        this.configManager.getMaxRetries()
      );

      console.log(`Repository cloned to: ${repoPath}`);
      return repoPath;
    } catch (error) {
      // Clean up on failure
      await this.cleanup(repoPath);
      
      if (error instanceof Error) {
        if (error.message.includes('Authentication failed') || error.message.includes('403')) {
          const tokenHint = this.configManager.getGitHubToken() 
            ? 'The provided GitHub token may be invalid or expired.' 
            : 'Consider setting a GitHub token via GITHUB_TOKEN environment variable for private repositories.';
          throw new Error(`Authentication failed. ${tokenHint} Repository: ${url}`);
        } else if (error.message.includes('Repository not found') || error.message.includes('404')) {
          throw new Error(`Repository not found: ${url}. Please check the URL and your access permissions.`);
        } else if (error.message.includes('timeout') || error.message.includes('Network')) {
          throw new Error(`Network error while cloning repository: ${url}. Please check your internet connection.`);
        }
      }
      
      throw new Error(`Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async findSolidityFiles(repoPath: string): Promise<string[]> {
    try {
      // Verify the repository path exists
      if (!(await fs.pathExists(repoPath))) {
        throw new Error(`Repository path does not exist: ${repoPath}`);
      }

      const solidityFiles: string[] = [];
      await this.traverseDirectory(repoPath, solidityFiles);

      console.log(`Found ${solidityFiles.length} Solidity files`);
      return solidityFiles.sort(); // Sort for consistent ordering
    } catch (error) {
      throw new Error(`Failed to find Solidity files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async readFileContent(filePath: string): Promise<string> {
    try {
      // Verify the file exists
      if (!(await fs.pathExists(filePath))) {
        throw new Error(`File does not exist: ${filePath}`);
      }

      // Check if it's actually a file (not a directory)
      const stats = await fs.stat(filePath);
      if (!stats.isFile()) {
        throw new Error(`Path is not a file: ${filePath}`);
      }

      // Read and return file content
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      throw new Error(`Failed to read file content: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async cleanup(repoPath: string): Promise<void> {
    try {
      if (await fs.pathExists(repoPath)) {
        await fs.remove(repoPath);
        console.log(`Cleaned up temporary directory: ${repoPath}`);
      }
    } catch (error) {
      console.warn(`Failed to cleanup directory ${repoPath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private isValidGitHubUrl(url: string): boolean {
    const githubUrlPattern = /^https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(?:\.git)?$/;
    return githubUrlPattern.test(url);
  }

  private extractRepoName(url: string): string {
    const match = url.match(/github\.com\/[^\/]+\/([^\/]+?)(?:\.git)?$/);
    return match ? match[1] : 'unknown-repo';
  }

  private prepareCloneUrl(url: string): string {
    const token = this.configManager.getGitHubToken();
    if (!token) {
      return url;
    }

    // Convert https://github.com/user/repo to https://token@github.com/user/repo
    return url.replace('https://github.com/', `https://${token}@github.com/`);
  }

  private async retryOperation<T>(
    operation: () => Promise<T>,
    maxRetries: number,
    delay: number = 1000
  ): Promise<T> {
    let lastError: Error;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        
        if (attempt === maxRetries) {
          break;
        }

        // Don't retry on authentication or not found errors
        if (lastError.message.includes('Authentication failed') || 
            lastError.message.includes('Repository not found') ||
            lastError.message.includes('403') ||
            lastError.message.includes('404')) {
          break;
        }

        console.log(`Attempt ${attempt} failed, retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2; // Exponential backoff
      }
    }

    throw lastError!;
  }

  private async traverseDirectory(dirPath: string, solidityFiles: string[]): Promise<void> {
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        // Skip common directories that typically don't contain source code
        if (entry.isDirectory()) {
          if (this.shouldSkipDirectory(entry.name)) {
            continue;
          }
          // Recursively traverse subdirectories
          await this.traverseDirectory(fullPath, solidityFiles);
        } else if (entry.isFile()) {
          // Check if it's a Solidity file
          if (this.isSolidityFile(entry.name)) {
            solidityFiles.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Log warning but don't fail the entire operation for individual directory issues
      console.warn(`Warning: Could not read directory ${dirPath}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private isSolidityFile(fileName: string): boolean {
    return fileName.toLowerCase().endsWith('.sol');
  }

  private shouldSkipDirectory(dirName: string): boolean {
    const skipDirs = new Set([
      'node_modules',
      '.git',
      '.github',
      'dist',
      'build',
      'out',
      'artifacts',
      'cache',
      'coverage',
      '.nyc_output',
      'docs',
      'documentation',
      'test-results',
      'allure-results',
      '.vscode',
      '.idea',
      'tmp',
      'temp',
      '.DS_Store',
      '__pycache__',
      '.pytest_cache'
    ]);

    return skipDirs.has(dirName) || dirName.startsWith('.');
  }
}