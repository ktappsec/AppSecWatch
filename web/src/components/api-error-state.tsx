"use client";

import Link from "next/link";
import { ServerCrash, Settings, AlertTriangle } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { getApiBase } from "@/lib/api";
import { ApiError } from "@/lib/api";

/** Compact inline error strip — for list pages that shouldn't lose their chrome. */
export function InlineError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <Card className="flex flex-row items-center gap-3 border-destructive/30 bg-destructive/5 p-4">
      <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
      <p className="flex-1 text-sm text-muted-foreground">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </Card>
  );
}

/** Full-width error panel for when the API is unreachable / returns an error. */
export function ApiErrorState({ error }: { error: Error }) {
  const isNetwork = error instanceof ApiError && error.status === 0;
  const isAuth = error instanceof ApiError && error.status === 401;
  return (
    <Card className="mx-auto mt-10 max-w-xl items-center gap-4 p-10 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-destructive/15 text-destructive">
        <ServerCrash className="h-7 w-7" />
      </div>
      <div>
        <h2 className="text-lg font-semibold">
          {isNetwork
            ? "Can't reach the AppSecWatch API"
            : isAuth
              ? "Authentication failed"
              : "Something went wrong"}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">{error.message}</p>
      </div>
      <div className="rounded-lg bg-secondary px-3 py-2 text-xs text-muted-foreground">
        API base: <span className="font-mono">{getApiBase()}</span>
      </div>
      <div className="flex gap-2">
        <Button asChild variant="outline" size="sm">
          <Link href="/settings">
            <Settings className="h-4 w-4" /> Configure API
          </Link>
        </Button>
        <Button size="sm" onClick={() => window.location.reload()}>
          Retry
        </Button>
      </div>
      {isNetwork && (
        <p className="text-xs text-muted-foreground">
          Start the backend with{" "}
          <span className="font-mono">appsecwatch serve -c example.server.yaml --port 8099</span>
        </p>
      )}
    </Card>
  );
}
