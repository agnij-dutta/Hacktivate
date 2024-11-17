import { NextResponse } from 'next/server';
import { getServerSession } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { runPythonAnalysis } from '@/lib/python-bridge';

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession();
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    const profile = await prisma.profile.findUnique({
      where: { id: params.id }
    });

    if (!profile) {
      return NextResponse.json(
        { error: 'Profile not found' },
        { status: 404 }
      );
    }

    // Get active hackathons
    const hackathons = await prisma.hackathon.findMany({
      where: {
        applicationDeadline: {
          gt: new Date()
        }
      }
    });

    // Use existing HackathonMatcher from Python code
    // Referenced in resume_analysis/main.py lines 86-89
    const matches = await runPythonAnalysis(
      null,
      profile.githubUsername,
      null,
      hackathons
    );

    return NextResponse.json({ recommendations: matches });
  } catch (error) {
    console.error('Recommendations error:', error);
    return NextResponse.json(
      { error: 'Failed to get recommendations' },
      { status: 500 }
    );
  }
} 