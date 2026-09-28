import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let client: SupabaseClient | null = null;

export function accountLoginAvailable() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || "";
  return Boolean(url && key && !url.startsWith("replace_with_") && !key.startsWith("replace_with_"));
}

export function supabaseBrowser() {
  if (!accountLoginAvailable()) return null;
  if (!client) {
    client = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
      { auth: { flowType: "pkce", detectSessionInUrl: true, persistSession: true, autoRefreshToken: true, storageKey: "yida-supabase-auth" } },
    );
  }
  return client;
}
