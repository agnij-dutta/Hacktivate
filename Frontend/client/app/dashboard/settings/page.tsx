"use client"
import React, { useState } from 'react';
import { Bell, Moon, Sun, Globe, Laptop } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

const SettingsPage = () => {
  const [darkMode, setDarkMode] = useState(false);
  const [emailNotifs, setEmailNotifs] = useState(true);
  const [pushNotifs, setPushNotifs] = useState(true);
  const [mentionNotifs, setMentionNotifs] = useState(true);
  const [teamNotifs, setTeamNotifs] = useState(true);

  return (
    <div className="container overflow-scroll space-y-8 w-full">
      <div className="space-y-2">
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-gray-500">Customize your hackathon experience</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Laptop className="w-5 h-5" />
            Appearance
          </CardTitle>
          <CardDescription>Customize how the hackathon platform looks</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {darkMode ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
                <Label>Theme</Label>
              </div>
              <p className="text-sm text-gray-500">Switch between light and dark mode</p>
            </div>
            <Switch checked={darkMode} onCheckedChange={setDarkMode} />
          </div>

          <Separator />

          <div className="space-y-2">
            <Label>Time Format</Label>
            <Select defaultValue="utc">
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select timezone" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="utc">UTC (GMT+0)</SelectItem>
                <SelectItem value="est">EST (GMT-5)</SelectItem>
                <SelectItem value="pst">PST (GMT-8)</SelectItem>
                <SelectItem value="ist">IST (GMT+5:30)</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-sm text-gray-500">Choose how times are displayed across the platform</p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="w-5 h-5" />
            Notifications
          </CardTitle>
          <CardDescription>Control when and how you want to be notified</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Email Notifications</Label>
              <p className="text-sm text-gray-500">Receive important updates via email</p>
            </div>
            <Switch checked={emailNotifs} onCheckedChange={setEmailNotifs} />
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Push Notifications</Label>
              <p className="text-sm text-gray-500">Get browser notifications for important events</p>
            </div>
            <Switch checked={pushNotifs} onCheckedChange={setPushNotifs} />
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Mention Notifications</Label>
              <p className="text-sm text-gray-500">Get notified when someone mentions you</p>
            </div>
            <Switch checked={mentionNotifs} onCheckedChange={setMentionNotifs} />
          </div>

          <Separator />

          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <Label>Team Updates</Label>
              <p className="text-sm text-gray-500">Get notified about team activity and messages</p>
            </div>
            <Switch checked={teamNotifs} onCheckedChange={setTeamNotifs} />
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end gap-4">
        <Button variant="outline">Reset to Defaults</Button>
        <Button>Save Changes</Button>
      </div>
    </div>
  );
};

export default SettingsPage;



