import { exec } from "child_process";
import { promisify } from "util";
import { writeFile, unlink, mkdir } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
import { v4 as uuidv4 } from "uuid";

const execAsync = promisify(exec);

// Types matching Rust output
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  severity: Severity;
  confidence: Confidence;
  line: number;
  vulnerability_type: string;
  message: string;
  suggestion: string;
  file?: string;
}

export interface Statistics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  confidence_high: number;
  confidence_medium: number;
  confidence_low: number;
}

export interface ScanResult {
  id: string;
  timestamp: string;
  filename: string;
  findings: Finding[];
  statistics: Statistics;
  source_code: string;
  scan_time_ms: number;
}

// Path to the Vanguard binary - ALWAYS use ./bin/vanguard first, then fall back
function getBinaryPath(): string {
  // Try production path first (works on Vercel and when binary is committed)
  const productionPath = path.join(process.cwd(), 'bin', 'vanguard');
  if (existsSync(productionPath)) {
    return productionPath;
  }
  
  // Fall back to development path (local cargo build)
  const devPath = path.join(process.cwd(), '..', 'core', 'target', 'release', 'core');
  if (existsSync(devPath)) {
    return devPath;
  }
  
  // If env var is set, use that
  if (process.env.VANGUARD_PATH) {
    return process.env.VANGUARD_PATH;
  }
  
  // Default to production path (will fail with clear error if not found)
  return productionPath;
}

const VANGUARD_BINARY = getBinaryPath();

// Always use /tmp on Vercel (writable), fall back to absolute path
const TEMP_DIR = process.env.NODE_ENV === 'production' 
  ? '/tmp/vanguard-scans'  // Vercel: use /tmp (always writable)
  : (process.env.TEMP_DIR || path.join(process.cwd(), 'tmp', 'vanguard-scans')); // Local: use project tmp

// In-memory store for scan results (replace with DB in production)
const scanResults = new Map<string, ScanResult>();

export async function scanContract(
  sourceCode: string,
  filename: string = "contract.sol"
): Promise<ScanResult> {
  const scanId = uuidv4();
  const startTime = Date.now();

  console.log('[Scanner] Binary path:', VANGUARD_BINARY);
  console.log('[Scanner] Temp dir:', TEMP_DIR);
  console.log('[Scanner] CWD:', process.cwd());
  console.log('[Scanner] NODE_ENV:', process.env.NODE_ENV);

  // Ensure temp directory exists
  await mkdir(TEMP_DIR, { recursive: true });
  console.log('[Scanner] Temp directory ready');

  // Write source to temp file
  const tempFile = path.join(TEMP_DIR, `${scanId}.sol`);
  await writeFile(tempFile, sourceCode, "utf-8");

  try {
    // Run Vanguard scanner
    // Note: The binary may exit with non-zero code when vulnerabilities are found
    // (e.g., exit code 2 = vulnerabilities detected), so we need to handle that
    let stdout = "";
    let stderr = "";
    
    const command = `${VANGUARD_BINARY} scan ${tempFile} --format json`;
    console.log('[Scanner] Executing command:', command);
    
    try {
      const result = await execAsync(
        command,
        { timeout: 30000 } // 30 second timeout
      );
      console.log('[Scanner] Command executed successfully');
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (execError: unknown) {
      // execAsync throws on non-zero exit codes, but we may still have valid output
      const err = execError as { stdout?: string; stderr?: string; code?: number };
      if (err.stdout) {
        stdout = err.stdout;
        stderr = err.stderr || "";
      } else {
        // No output means actual failure
        throw execError;
      }
    }

    // Log any warnings or errors from stderr
    if (stderr) {
      console.warn(`Vanguard scanner stderr: ${stderr}`);
    }

    const endTime = Date.now();

    // Parse JSON output
    let scanOutput: { findings: Finding[]; statistics: Statistics };
    try {
      scanOutput = JSON.parse(stdout);
    } catch {
      // If JSON parsing fails, create empty result
      scanOutput = {
        findings: [],
        statistics: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          confidence_high: 0,
          confidence_medium: 0,
          confidence_low: 0,
        },
      };
    }

    const result: ScanResult = {
      id: scanId,
      timestamp: new Date().toISOString(),
      filename,
      findings: scanOutput.findings,
      statistics: scanOutput.statistics,
      source_code: sourceCode,
      scan_time_ms: endTime - startTime,
    };

    // Store result
    scanResults.set(scanId, result);

    return result;
  } finally {
    // Cleanup temp file
    try {
      await unlink(tempFile);
    } catch {
      // Ignore cleanup errors
    }
  }
}

export async function getScanResult(id: string): Promise<ScanResult | null> {
  return scanResults.get(id) || null;
}

export function getRecentScans(limit: number = 10): ScanResult[] {
  return Array.from(scanResults.values())
    .sort(
      (a, b) =>
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    )
    .slice(0, limit);
}

// Mock scanner for development/demo without Rust binary
export async function mockScanContract(
  sourceCode: string,
  filename: string = "contract.sol"
): Promise<ScanResult> {
  const scanId = uuidv4();
  const startTime = Date.now();

  // Simulate processing time
  await new Promise((resolve) =>
    setTimeout(resolve, 500 + Math.random() * 1000)
  );

  // Simple pattern detection for demo
  const findings: Finding[] = [];
  const lines = sourceCode.split("\n");

  lines.forEach((line, index) => {
    const lineNum = index + 1;

    // Reentrancy pattern
    if (
      line.includes(".call{value") ||
      line.includes(".transfer(") ||
      line.includes(".send(")
    ) {
      findings.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: lineNum,
        vulnerability_type: "Potential Reentrancy",
        message:
          "External call detected - verify state changes occur before this call",
        suggestion:
          "Use checks-effects-interactions pattern or add nonReentrant modifier",
      });
    }

    // tx.origin
    if (line.includes("tx.origin")) {
      findings.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: lineNum,
        vulnerability_type: "tx.origin Authentication",
        message: "Using tx.origin for authorization is vulnerable to phishing",
        suggestion: "Use msg.sender instead of tx.origin",
      });
    }

    // Unchecked call
    if (
      line.includes(".call(") &&
      !line.includes("require") &&
      !line.includes("bool")
    ) {
      findings.push({
        severity: "MEDIUM",
        confidence: "MEDIUM",
        line: lineNum,
        vulnerability_type: "Unchecked Call",
        message: "Return value of external call not checked",
        suggestion:
          "Check return value: (bool success, ) = addr.call(...); require(success);",
      });
    }

    // Timestamp dependence
    if (
      line.includes("block.timestamp") &&
      (line.includes("==") || line.includes("%"))
    ) {
      findings.push({
        severity: "MEDIUM",
        confidence: "MEDIUM",
        line: lineNum,
        vulnerability_type: "Timestamp Dependence",
        message: "Exact timestamp comparison can be manipulated by miners",
        suggestion: "Use block.timestamp only for >15 minute precision",
      });
    }

    // Unsafe ERC20
    if (
      (line.includes(".transfer(") || line.includes(".transferFrom(")) &&
      !line.includes("safeTransfer") &&
      !line.includes("require")
    ) {
      findings.push({
        severity: "HIGH",
        confidence: "HIGH",
        line: lineNum,
        vulnerability_type: "Unchecked ERC20 Transfer",
        message: "ERC20 transfer return value not checked",
        suggestion: "Use SafeERC20.safeTransfer() or check return value",
      });
    }
  });

  // Calculate statistics
  const statistics: Statistics = {
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
    confidence_high: findings.filter((f) => f.confidence === "HIGH").length,
    confidence_medium: findings.filter((f) => f.confidence === "MEDIUM").length,
    confidence_low: findings.filter((f) => f.confidence === "LOW").length,
  };

  const endTime = Date.now();

  const result: ScanResult = {
    id: scanId,
    timestamp: new Date().toISOString(),
    filename,
    findings,
    statistics,
    source_code: sourceCode,
    scan_time_ms: endTime - startTime,
  };

  scanResults.set(scanId, result);

  return result;
}
