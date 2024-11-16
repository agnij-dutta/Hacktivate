"use client"
import { useEffect, useState } from 'react';
import { apiClient } from '@/lib/api-client';
import { useAuth } from '@/hooks/useAuth';
import { Calendar, Users, Trophy, Clock, ArrowRight, Search } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

// Define types

interface Hackathon {
  id: string;
  name: string;
  description: string;
  primary_track: string;
  difficulty: string;
  start_date: string;
  end_date: string;
  application_deadline: string;
  prize_pool: number;
  external_url?: string;
  quick_apply_enabled: boolean;
  status: string;
}

interface HackathonCardProps {
  hackathon: Hackathon;
}

type HackathonStatus = 'Live' | 'Upcoming' | 'Completed';

interface Hackathon {
  name: string;
  organizer: string;
  status: HackathonStatus;
  image: string;
  date: string;
  participants: number;
  prize: number;
  duration: number;
  description: string;
  tags: string[];
}

interface HackathonCardProps {
  hackathon: Hackathon;
}

const HackathonCard: React.FC<HackathonCardProps> = ({ hackathon }) => (
  <Card className="group hover:shadow-lg transition-all duration-300 hover:scale-[1.01]">
    <CardHeader className="space-y-2">
      <div className="flex flex-col sm:flex-row justify-between sm:items-start gap-2">
        <div className="space-y-1">
          <CardTitle className="text-lg sm:text-xl font-bold line-clamp-1">{hackathon.name}</CardTitle>
          <CardDescription className="line-clamp-1">{hackathon.organizer}</CardDescription>
        </div>
        <Badge 
          variant={
            hackathon.status === 'Live' ? 'destructive' : 
            hackathon.status === 'Upcoming' ? 'default' : 
            'secondary'
          }
          className="w-fit"
        >
          {hackathon.status}
        </Badge>
      </div>
    </CardHeader>
    <CardContent className="space-y-4">
      <div className="aspect-video relative rounded-lg overflow-hidden">
        <img 
          src={hackathon.image} 
          alt={hackathon.name}
          className="w-full h-full object-cover"
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-gray-500 flex-shrink-0" />
          <span className="text-sm truncate">{hackathon.date}</span>
        </div>
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-gray-500 flex-shrink-0" />
          <span className="text-sm truncate">{hackathon.participants} teams</span>
        </div>
        <div className="flex items-center gap-2">
          <Trophy className="w-4 h-4 text-gray-500 flex-shrink-0" />
          <span className="text-sm truncate">${hackathon.prize.toLocaleString()} in prizes</span>
        </div>
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-gray-500 flex-shrink-0" />
          <span className="text-sm truncate">{hackathon.duration} hours</span>
        </div>
      </div>
      <p className="text-sm text-gray-600 line-clamp-2">{hackathon.description}</p>
    </CardContent>
    <CardFooter className="flex flex-col sm:flex-row gap-4 justify-between">
      <div className="flex flex-wrap gap-2">
        {hackathon.tags.map((tag, index) => (
          <Badge key={index} variant="outline" className="text-xs">{tag}</Badge>
        ))}
      </div>
      <Button size="sm" className="w-full sm:w-auto group-hover:translate-x-1 transition-transform">
        View Details
        <ArrowRight className="w-4 h-4 ml-2" />
      </Button>
    </CardFooter>
  </Card>
);


export default function HackathonDashboard() {
  const [hackathons, setHackathons] = useState<Hackathon[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTrack, setSelectedTrack] = useState('all');
  const { user } = useAuth();

  useEffect(() => {
    loadHackathons();
  }, [searchQuery, selectedTrack]);

  const loadHackathons = async () => {
    try {
      const response = await apiClient.hackathons.list({
        query: searchQuery || undefined,
        track: selectedTrack === 'all' ? undefined : selectedTrack
      });
      setHackathons(response.data.hackathons);
    } catch (error) {
      console.error('Failed to load hackathons:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto py-10 space-y-8">
      {/* Header Section */}
      <div className="flex justify-between items-center">
        <div className="space-y-1">
          <h1 className="text-3xl font-bold">Hackathons</h1>
          <p className="text-gray-500">Discover and participate in exciting hackathons</p>
        </div>
       </div>

      {/* Search and Filter Section */}
      <div className="flex gap-4 items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500 w-4 h-4" />
          <Input
            placeholder="Search hackathons..."
            className="pl-10"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <Select defaultValue="all">
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Filter by type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Hackathons</SelectItem>
            <SelectItem value="ai">AI & ML</SelectItem>
            <SelectItem value="web3">Web3</SelectItem>
            <SelectItem value="mobile">Mobile</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Tabs Section */}
      <Tabs defaultValue="all" className="space-y-6" value={selectedTrack} onValueChange={setSelectedTrack}>
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="Live">Live</TabsTrigger>
          <TabsTrigger value="Upcoming">Upcoming</TabsTrigger>
          <TabsTrigger value="Completed">Completed</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {hackathons.map((hackathon, index) => (
              <HackathonCard key={index} hackathon={hackathon} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="Live">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {hackathons.filter(hackathon => hackathon.status === 'Live').map((hackathon, index) => (
              <HackathonCard key={index} hackathon={hackathon} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="Upcoming">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {hackathons.filter(hackathon => hackathon.status === 'Upcoming').map((hackathon, index) => (
              <HackathonCard key={index} hackathon={hackathon} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="Completed">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {hackathons.filter(hackathon => hackathon.status === 'Completed').map((hackathon, index) => (
              <HackathonCard key={index} hackathon={hackathon} />
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}