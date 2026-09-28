"use client";

import { createContext, type FormEvent, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { accountLoginAvailable, supabaseBrowser } from "../lib/supabase-browser";
import { LayraMark } from "./layra-mark";

type Provider = "invite" | "account";
type AuthView = "email" | "register" | "forgot" | "reset" | "invite";
type AuthContextValue = { logout: () => Promise<void>; provider: Provider };
type AuthPayload = { authenticated?: boolean; provider?: Provider; inviteAvailable?: boolean; error?: string; code?: string };

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth 必须在 AuthGate 内使用");
  return value;
}

async function readPayload(response: Response): Promise<AuthPayload> {
  return response.json().catch(() => ({})) as Promise<AuthPayload>;
}

export function AuthGate({ children }: { children: ReactNode }) {
  const accountAvailable = accountLoginAvailable();
  const [state, setState] = useState<"checking" | "authenticated" | "anonymous">("checking");
  const [provider, setProvider] = useState<Provider>("invite");
  const [view, setView] = useState<AuthView>(accountAvailable ? "email" : "invite");
  const [inviteAvailable, setInviteAvailable] = useState(true);
  const [inviteCode, setInviteCode] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [messageIsSuccess, setMessageIsSuccess] = useState(false);

  const establishAccountSession = useCallback(async (accessToken: string) => {
    const response = await fetch("/api/auth/account/session", {
      method: "POST", headers: { "Content-Type": "application/json" },
      credentials: "same-origin", cache: "no-store", body: JSON.stringify({ accessToken }),
    });
    const payload = await readPayload(response);
    if (!response.ok || !payload.authenticated) throw new Error(payload.error || "账号验证失败，请重新登录");
    setProvider("account");
    setState("authenticated");
  }, []);

  useEffect(() => {
    let active = true;
    const check = async () => {
      try {
        const client = supabaseBrowser();
        const params = new URLSearchParams(window.location.search);
        const callback = params.has("code") || params.has("error") || params.get("type") === "recovery";
        if (client && callback) {
          const { data, error } = await client.auth.getSession();
          if (!active) return;
          if (error) throw error;
          if (params.get("type") === "recovery" && data.session) {
            setView("reset");
            setState("anonymous");
            return;
          }
          if (data.session) {
            await establishAccountSession(data.session.access_token);
            window.history.replaceState({}, "", window.location.pathname);
            return;
          }
        }
        const response = await fetch("/api/auth/session", { credentials: "same-origin", cache: "no-store" });
        const payload = await readPayload(response);
        if (!active) return;
        setInviteAvailable(payload.inviteAvailable !== false);
        if (!response.ok && client) {
          const { data } = await client.auth.getSession();
          if (!active) return;
          if (data.session) {
            await establishAccountSession(data.session.access_token);
            return;
          }
        }
        setProvider(payload.provider || "invite");
        setState(response.ok && payload.authenticated ? "authenticated" : "anonymous");
        if (response.status === 503) setMessage(payload.error || "登录服务尚未配置，请联系管理员");
      } catch (error) {
        if (!active) return;
        setState("anonymous");
        setMessage(error instanceof Error ? error.message : "暂时无法连接登录服务，请稍后重试");
      }
    };
    void check();
    const requireLogin = () => setState("anonymous");
    window.addEventListener("yida:auth-required", requireLogin);
    return () => { active = false; window.removeEventListener("yida:auth-required", requireLogin); };
  }, [establishAccountSession]);

  const loginWithInvite = async () => {
    const response = await fetch("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      cache: "no-store", body: JSON.stringify({ inviteCode: inviteCode.trim() }),
    });
    const payload = await readPayload(response);
    if (!response.ok || !payload.authenticated) throw new Error(payload.error || "邀请码无效，请确认后重试");
    await supabaseBrowser()?.auth.signOut().catch(() => undefined);
    setInviteCode("");
    setProvider("invite");
    setState("authenticated");
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setMessage("");
    setMessageIsSuccess(false);
    try {
      if (view === "invite") {
        await loginWithInvite();
        return;
      }
      const client = supabaseBrowser();
      if (!client) throw new Error("账号登录尚未配置，请使用邀请码");
      if (view === "email") {
        const { data, error } = await client.auth.signInWithPassword({ email: email.trim(), password });
        if (error || !data.session) throw new Error(error?.message || "邮箱或密码不正确");
        await establishAccountSession(data.session.access_token);
      } else if (view === "register") {
        const { data, error } = await client.auth.signUp({ email: email.trim(), password, options: { emailRedirectTo: window.location.origin } });
        if (error) throw error;
        if (data.session) await establishAccountSession(data.session.access_token);
        else { setMessage("注册邮件已发送，请打开邮箱完成验证后登录。"); setMessageIsSuccess(true); }
      } else if (view === "forgot") {
        const { error } = await client.auth.resetPasswordForEmail(email.trim(), { redirectTo: `${window.location.origin}/?type=recovery` });
        if (error) throw error;
        setMessage("若该邮箱已注册，密码重置邮件已发送。");
        setMessageIsSuccess(true);
      } else if (view === "reset") {
        const { error } = await client.auth.updateUser({ password });
        if (error) throw error;
        const { data } = await client.auth.getSession();
        if (data.session) await establishAccountSession(data.session.access_token);
        window.history.replaceState({}, "", window.location.pathname);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "操作失败，请稍后重试");
    } finally {
      setSubmitting(false);
    }
  };

  const oauth = async (selected: "google" | "github") => {
    const client = supabaseBrowser();
    if (!client) return;
    setMessage("");
    const { error } = await client.auth.signInWithOAuth({ provider: selected, options: { redirectTo: window.location.origin } });
    if (error) setMessage(error.message);
  };

  const logout = useCallback(async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", cache: "no-store" });
      await supabaseBrowser()?.auth.signOut();
    } finally {
      for (let index = window.sessionStorage.length - 1; index >= 0; index--) {
        const key = window.sessionStorage.key(index);
        if (key?.startsWith("yida:")) window.sessionStorage.removeItem(key);
      }
      window.localStorage.removeItem("yida:city");
      window.localStorage.removeItem("yida:location");
      window.localStorage.removeItem("yida:generations");
      setProvider("invite");
      setView(accountLoginAvailable() ? "email" : "invite");
      setState("anonymous");
      setMessage("");
    }
  }, []);

  if (state === "checking") {
    return <main className="auth-shell"><section className="auth-card auth-loading" aria-live="polite"><span className="auth-mark"><LayraMark /></span><p>正在确认登录状态…</p></section></main>;
  }

  if (state === "anonymous") {
    return <main className="auth-shell"><section className="auth-card">
      <div className="auth-brand"><span className="auth-mark"><LayraMark /></span><div><b>LAYRA</b><small>AI OUTFIT STUDIO</small></div></div>
      <div className="auth-copy"><span>PRIVATE WARDROBE</span><h1>{view === "register" ? "创建你的私人衣柜" : view === "forgot" ? "找回密码" : view === "reset" ? "设置新密码" : "欢迎回到你的私人衣柜"}</h1><p>{view === "invite" ? "输入分配给你的邀请码。同一邀请码在不同设备登录，都会回到同一个衣柜。" : view === "register" ? "使用邮箱创建账号，衣柜和搭配会保存在你的账号中。" : view === "forgot" ? "输入注册邮箱，我们会发送密码重置邮件。" : view === "reset" ? "设置新密码后即可继续使用。" : "使用邮箱或已关联的第三方账号登录。"}</p></div>
      <form className="auth-form" onSubmit={submit}>
        {view === "invite" ? <><label htmlFor="invite-code">邀请码</label><input id="invite-code" type="password" value={inviteCode} onChange={event => setInviteCode(event.target.value)} placeholder="请输入邀请码" autoComplete="current-password" maxLength={128} autoFocus /></> : <>
          {view !== "reset" && <><label htmlFor="account-email">邮箱</label><input id="account-email" type="email" value={email} onChange={event => setEmail(event.target.value)} placeholder="name@example.com" autoComplete="email" required autoFocus /></>}
          {view !== "forgot" && <><label htmlFor="account-password">{view === "reset" ? "新密码" : "密码"}</label><input id="account-password" type="password" value={password} onChange={event => setPassword(event.target.value)} placeholder="至少 6 位" autoComplete={view === "email" ? "current-password" : "new-password"} minLength={6} required /></>}
        </>}
        {message && <p className={messageIsSuccess ? "auth-success" : "auth-error"} role="status">{message}</p>}
        <button type="submit" disabled={submitting || (view === "invite" && !inviteCode.trim())}>{submitting ? "正在处理…" : view === "invite" ? "进入 LAYRA" : view === "register" ? "创建账号" : view === "forgot" ? "发送重置邮件" : view === "reset" ? "保存新密码" : "登录"}<span>→</span></button>
      </form>
      {accountAvailable && view === "email" && <><div className="auth-divider">或使用</div><div className="auth-oauth"><button onClick={() => void oauth("google")}>Google</button><button onClick={() => void oauth("github")}>GitHub</button></div></>}
      <div className="auth-links">
        {accountAvailable && (view === "register" || view === "forgot") && <button onClick={() => { setView("email"); setMessage(""); }}>邮箱登录</button>}
        {accountAvailable && view === "email" && <><button onClick={() => { setView("register"); setMessage(""); }}>注册账号</button><button onClick={() => { setView("forgot"); setMessage(""); }}>忘记密码</button></>}
        {accountAvailable && view !== "reset" && (inviteAvailable || view === "invite") && <button onClick={() => { setView(view === "invite" ? "email" : "invite"); setMessage(""); }}>{view === "invite" ? "使用账号登录" : "使用邀请码"}</button>}
      </div>
      <p className="auth-footnote">{view === "invite" ? "邀请码只用于识别你的个人数据，请勿转发给其他人。" : "照片与衣柜数据仅在你的账号下可见。"}</p>
    </section></main>;
  }

  return <AuthContext.Provider value={{ logout, provider }}>{children}</AuthContext.Provider>;
}
