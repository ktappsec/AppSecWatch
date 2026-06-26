"use client";

import { Toaster as Sonner } from "sonner";
import { useTheme } from "@/components/theme-provider";

type ToasterProps = React.ComponentProps<typeof Sonner>;

export function Toaster(props: ToasterProps) {
  const { resolvedTheme } = useTheme();
  return (
    <Sonner
      theme={resolvedTheme}
      position="top-right"
      richColors
      toastOptions={{
        classNames: {
          toast: "rounded-lg border border-border bg-card text-card-foreground shadow-lg",
        },
      }}
      {...props}
    />
  );
}

export { toast } from "sonner";
