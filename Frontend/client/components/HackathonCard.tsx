import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { apiClient } from '@/lib/api-client';
import { useAuth } from '@/hooks/useAuth';

export function HackathonCard({ hackathon }) {
  const [applying, setApplying] = useState(false);
  const { user, profile } = useAuth();

  const handleApply = async () => {
    if (!profile) {
      // Redirect to profile creation if needed
      router.push('/profile/create');
      return;
    }

    try {
      setApplying(true);
      await apiClient.hackathons.apply(hackathon.id, {
        profileId: profile.id,
        applyType: hackathon.quick_apply_enabled ? 'quick' : 'normal'
      });
      
      if (hackathon.quick_apply_enabled) {
        toast.success('Application submitted successfully!');
      } else {
        window.location.href = hackathon.external_url;
      }
    } catch (error) {
      toast.error('Failed to submit application');
    } finally {
      setApplying(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{hackathon.name}</CardTitle>
      </CardHeader>
      <CardContent>
        {/* Card content */}
        <Button 
          onClick={handleApply} 
          disabled={applying}
        >
          {applying ? 'Applying...' : 'Apply Now'}
        </Button>
      </CardContent>
    </Card>
  );
} 