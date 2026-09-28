import { NextResponse } from "next/server";
import {
  AuthConfigurationError,
  LEGACY_OWNER_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  accountUserId,
  createSessionToken,
  expiredCookieOptions,
  sessionCookieOptions,
} from "../../../../lib/auth";

export async function POST(request: Request) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim();
  if (!url || !key || url.startsWith("replace_with_") || key.startsWith("replace_with_")) {
    return NextResponse.json({ error: "账号登录尚未配置", code: "ACCOUNT_AUTH_NOT_CONFIGURED" }, { status: 503 });
  }
  const body = await request.json().catch(() => null) as { accessToken?: unknown } | null;
  const accessToken = typeof body?.accessToken === "string" ? body.accessToken : "";
  if (!accessToken || accessToken.length > 5000) return NextResponse.json({ error: "登录凭证无效" }, { status: 400 });
  try {
    const verification = await fetch(`${url.replace(/\/$/, "")}/auth/v1/user`, {
      headers: { apikey: key, Authorization: `Bearer ${accessToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    if (!verification.ok) return NextResponse.json({ error: "登录状态无效，请重新登录" }, { status: 401 });
    const user = await verification.json() as { id?: string; email?: string };
    if (!user.id || !user.email) return NextResponse.json({ error: "账号资料不完整" }, { status: 401 });
    const ownerId = accountUserId(user.id);
    const response = NextResponse.json({ authenticated: true, provider: "account", email: user.email });
    response.cookies.set(SESSION_COOKIE_NAME, createSessionToken(ownerId, Date.now(), "account"), sessionCookieOptions());
    response.cookies.set(LEGACY_OWNER_COOKIE_NAME, "", expiredCookieOptions());
    response.headers.set("Cache-Control", "no-store");
    return response;
  } catch (error) {
    if (error instanceof AuthConfigurationError) return NextResponse.json({ error: "登录服务尚未配置" }, { status: 503 });
    return NextResponse.json({ error: "账号验证暂时不可用，请稍后重试" }, { status: 503 });
  }
}
