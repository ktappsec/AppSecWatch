"use client";

import * as React from "react";
import { Save, Plug, KeyRound } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { toast } from "@/components/ui/sonner";
import { api, getApiBase, getApiKey, setApiConfig, ApiError } from "@/lib/api";
import { useMounted } from "@/lib/hooks";
import { ScanConfigCard } from "@/components/settings/scan-config";

export default function SettingsPage() {
  const mounted = useMounted();
  const [base, setBase] = React.useState("");
  const [key, setKey] = React.useState("");
  const [testing, setTesting] = React.useState(false);

  React.useEffect(() => {
    if (mounted) {
      setBase(getApiBase());
      setKey(getApiKey());
    }
  }, [mounted]);

  const save = () => {
    setApiConfig(base, key);
    toast.success("Settings saved");
  };

  const test = async () => {
    setApiConfig(base, key); // apply before testing
    setTesting(true);
    try {
      const h = await api.health();
      toast.success(`API online — v${h.version}`);
      try {
        await api.capabilities();
        toast.success("Authentication OK");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) toast.error("Auth failed (check API key)");
      }
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Connection failed");
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Connect the UI to your AppSecWatch FastAPI backend. Stored locally in your browser.
        </p>
      </div>

      <Card className="gap-5 p-6">
        <div className="flex items-center gap-2">
          <Plug className="h-5 w-5 text-primary" />
          <h3 className="text-lg font-semibold">API connection</h3>
        </div>

        <div className="space-y-1.5">
          <Label>API base URL</Label>
          <Input
            value={base}
            onChange={(e) => setBase(e.target.value)}
            placeholder="http://127.0.0.1:8099"
          />
          <p className="text-xs text-muted-foreground">
            Where <span className="font-mono">appsecwatch serve</span> is listening.
          </p>
        </div>

        <div className="space-y-1.5">
          <Label className="flex items-center gap-1.5">
            <KeyRound className="h-3.5 w-3.5" /> API key
          </Label>
          <Input
            type="password"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="Bearer token (leave blank if auth disabled)"
          />
          <p className="text-xs text-muted-foreground">
            Sent as <span className="font-mono">Authorization: Bearer …</span>. Matches an entry in{" "}
            <span className="font-mono">APPSECWATCH_API_KEYS</span>.
          </p>
        </div>

        <Separator />

        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={test} disabled={testing}>
            {testing ? "Testing…" : "Test connection"}
          </Button>
          <Button onClick={save} className="gap-1.5">
            <Save className="h-4 w-4" /> Save
          </Button>
        </div>
      </Card>

      <ScanConfigCard />
    </div>
  );
}
