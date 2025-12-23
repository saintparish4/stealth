import { NextRequest, NextResponse } from 'next/server'
import { mockScanContract, scanContract } from '../../lib/scanner'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { code, filename } = body

    if (!code || typeof code !== 'string') {
      return NextResponse.json(
        { error: 'Invalid request: code is required' },
        { status: 400 }
      )
    }

    // Use mock scanner only if explicitly set
    const useMock = process.env.USE_MOCK_SCANNER === 'true'
    
    const result = useMock 
      ? await mockScanContract(code, filename || 'contract.sol')
      : await scanContract(code, filename || 'contract.sol')

    return NextResponse.json(result)
  } catch (error) {
    console.error('Scan error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

export async function GET() {
  return NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405 }
  )
}