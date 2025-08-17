import { GitHubRepositoryManager } from '../../core/RepositoryManager';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';

describe('File Discovery Integration Tests', () => {
  let repositoryManager: GitHubRepositoryManager;
  let testRepoPath: string;

  beforeAll(async () => {
    repositoryManager = new GitHubRepositoryManager();
    
    // Create a temporary test repository structure
    testRepoPath = path.join(os.tmpdir(), 'test-solidity-repo');
    await fs.ensureDir(testRepoPath);
    
    // Create test directory structure
    const structure = {
      'Contract.sol': 'pragma solidity ^0.8.0;\n\ncontract Contract {}',
      'src/Token.sol': 'pragma solidity ^0.8.0;\n\ncontract Token {}',
      'src/interfaces/IERC20.sol': 'pragma solidity ^0.8.0;\n\ninterface IERC20 {}',
      'src/utils/Helper.sol': 'pragma solidity ^0.8.0;\n\nlibrary Helper {}',
      'test/Contract.test.sol': 'pragma solidity ^0.8.0;\n\ncontract ContractTest {}',
      'README.md': '# Test Repository',
      'package.json': '{"name": "test"}',
      'node_modules/package/Contract.sol': 'should be ignored',
      '.git/objects/Contract.sol': 'should be ignored',
      'build/Contract.sol': 'should be ignored'
    };

    for (const [filePath, content] of Object.entries(structure)) {
      const fullPath = path.join(testRepoPath, filePath);
      await fs.ensureDir(path.dirname(fullPath));
      await fs.writeFile(fullPath, content);
    }
  });

  afterAll(async () => {
    // Clean up test repository
    if (await fs.pathExists(testRepoPath)) {
      await fs.remove(testRepoPath);
    }
  });

  describe('findSolidityFiles', () => {
    it('should find all Solidity files while skipping ignored directories', async () => {
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);

      expect(solidityFiles).toHaveLength(5);
      expect(solidityFiles).toContain(path.join(testRepoPath, 'Contract.sol'));
      expect(solidityFiles).toContain(path.join(testRepoPath, 'src', 'Token.sol'));
      expect(solidityFiles).toContain(path.join(testRepoPath, 'src', 'interfaces', 'IERC20.sol'));
      expect(solidityFiles).toContain(path.join(testRepoPath, 'src', 'utils', 'Helper.sol'));
      expect(solidityFiles).toContain(path.join(testRepoPath, 'test', 'Contract.test.sol'));

      // Verify ignored directories are not included
      expect(solidityFiles).not.toContain(path.join(testRepoPath, 'node_modules', 'package', 'Contract.sol'));
      expect(solidityFiles).not.toContain(path.join(testRepoPath, '.git', 'objects', 'Contract.sol'));
      expect(solidityFiles).not.toContain(path.join(testRepoPath, 'build', 'Contract.sol'));
    });

    it('should return sorted file paths', async () => {
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);

      // Verify files are sorted
      const sortedFiles = [...solidityFiles].sort();
      expect(solidityFiles).toEqual(sortedFiles);
    });
  });

  describe('readFileContent', () => {
    it('should read content from discovered Solidity files', async () => {
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);
      
      for (const filePath of solidityFiles) {
        const content = await repositoryManager.readFileContent(filePath);
        
        expect(content).toBeTruthy();
        expect(content).toContain('pragma solidity');
        expect(typeof content).toBe('string');
      }
    });

    it('should handle different file contents correctly', async () => {
      const contractPath = path.join(testRepoPath, 'Contract.sol');
      const tokenPath = path.join(testRepoPath, 'src', 'Token.sol');

      const contractContent = await repositoryManager.readFileContent(contractPath);
      const tokenContent = await repositoryManager.readFileContent(tokenPath);

      expect(contractContent).toContain('contract Contract');
      expect(tokenContent).toContain('contract Token');
      expect(contractContent).not.toEqual(tokenContent);
    });
  });

  describe('complete workflow', () => {
    it('should discover and read all Solidity files in a repository', async () => {
      // Discover files
      const solidityFiles = await repositoryManager.findSolidityFiles(testRepoPath);
      expect(solidityFiles.length).toBeGreaterThan(0);

      // Read all discovered files
      const fileContents = new Map<string, string>();
      
      for (const filePath of solidityFiles) {
        const content = await repositoryManager.readFileContent(filePath);
        fileContents.set(filePath, content);
      }

      // Verify all files were read successfully
      expect(fileContents.size).toBe(solidityFiles.length);
      
      // Verify content quality
      for (const [filePath, content] of fileContents) {
        expect(content).toBeTruthy();
        expect(content.length).toBeGreaterThan(0);
        expect(filePath.endsWith('.sol')).toBe(true);
      }
    });
  });
});