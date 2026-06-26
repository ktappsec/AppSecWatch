import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** The one class-merge helper. Always use it for dynamic className composition —
 * without tailwind-merge, conflicting utilities (e.g. `p-4 p-6`) both apply. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
