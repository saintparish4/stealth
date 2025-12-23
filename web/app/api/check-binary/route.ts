import { NextResponse } from 'next/server';
import { existsSync, statSync, readdirSync } from 'fs';
import path from 'path';

export async function GET() {
  const cwd = process.cwd();
  const binaryPath = path.join(cwd, 'bin', 'vanguard');
  
  try {
    const exists = existsSync(binaryPath);
    
    if (exists) {
      const stats = statSync(binaryPath);
      return NextResponse.json({
        status: 'found',
        exists: true,
        path: binaryPath,
        size: stats.size,
        sizeReadable: `${(stats.size / 1024 / 1024).toFixed(2)} MB`,
        mode: stats.mode.toString(8),
        isFile: stats.isFile(),
        isExecutable: (stats.mode & 0o111) !== 0,
        cwd: cwd,
        nodeEnv: process.env.NODE_ENV
      });
    }
    
    // Binary not found - show what's in the directory
    const binDirExists = existsSync(path.join(cwd, 'bin'));
    const binContents = binDirExists ? readdirSync(path.join(cwd, 'bin')) : [];
    const rootContents = readdirSync(cwd);
    
    return NextResponse.json({
      status: 'not_found',
      exists: false,
      path: binaryPath,
      cwd: cwd,
      binDirExists: binDirExists,
      binContents: binContents,
      rootContents: rootContents.slice(0, 20), // First 20 files
      nodeEnv: process.env.NODE_ENV
    });
  } catch (error) {
    return NextResponse.json({
      status: 'error',
      error: (error as Error).message,
      cwd: cwd,
      nodeEnv: process.env.NODE_ENV
    }, { status: 500 });
  }
}

