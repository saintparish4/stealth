import { NextRequest, NextResponse } from 'next/server'
import { getScanResult } from '../../../lib/scanner'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const result = await getScanResult(params.id)
    
    if (!result) {
      return NextResponse.json(
        { error: 'Scan result not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(result)
  } catch (error) {
    console.error('Error fetching scan result:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}