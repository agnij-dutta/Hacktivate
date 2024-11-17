import { NextResponse } from 'next/server';
import { getServerSession } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { PythonService } from '@/lib/python-service';
import { uploadFile } from '@/lib/storage';

export async function POST(request: Request) {
  try {
    const session = await getServerSession();
    if (!session) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    const formData = await request.formData();
    const name = formData.get('name') as string;
    const githubUsername = formData.get('github_username') as string;
    const linkedinUrl = formData.get('linkedin_url') as string;
    const resumeFile = formData.get('resume_file') as File;
    const linkedinFile = formData.get('linkedin_file') as File | null;

    // Upload files
    const resumeBuffer = Buffer.from(await resumeFile.arrayBuffer());
    const linkedinBuffer = linkedinFile ? 
      Buffer.from(await linkedinFile.arrayBuffer()) : null;

    const [resumePath, linkedinPath] = await Promise.all([
      uploadFile(resumeBuffer, 'resumes', resumeFile.name),
      linkedinFile ? uploadFile(linkedinBuffer!, 'linkedin', linkedinFile.name) : null
    ]);

    // Analyze profile
    const pythonService = PythonService.getInstance();
    const analysis = await pythonService.analyzeProfile(
      resumeBuffer,
      githubUsername,
      linkedinBuffer
    );

    // Create profile
    const profile = await prisma.profile.create({
      data: {
        userId: session.userId,
        name,
        githubUsername,
        linkedinUrl,
        resumePath,
        linkedinPath,
        analysisResults: analysis
      }
    });

    return NextResponse.json({
      profile_id: profile.id,
      analysis
    });
  } catch (error) {
    console.error('Profile creation error:', error);
    return NextResponse.json(
      { error: 'Failed to create profile' },
      { status: 500 }
    );
  }
} 