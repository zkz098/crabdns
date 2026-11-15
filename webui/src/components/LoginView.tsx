import { createSignal, Show } from "solid-js";
import { t } from "../i18n";

interface LoginViewProps {
  onLogin: (username: string, password: string) => Promise<string | null>;
}

export function LoginView(props: LoginViewProps) {
  const [username, setUsername] = createSignal("admin");
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    const err = await props.onLogin(username(), password());
    setSubmitting(false);
    if (err) {
      setError(err);
    }
  }

  return (
    <div class="min-h-screen flex items-center justify-center px-4 bg-[#fafafa] dark:bg-black text-[#171717] dark:text-[#ededed]">
      <div class="w-full max-w-sm rounded-2xl border border-[#eaeaea] dark:border-[#262626] bg-white dark:bg-[#0a0a0a] p-6 sm:p-7 shadow-sm space-y-6">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-xl bg-[#171717] dark:bg-white text-white dark:text-[#0a0a0a] flex items-center justify-center shrink-0">
            <span class="i-ri-shield-check-fill text-lg" />
          </div>
          <div>
            <h1 class="text-base font-semibold tracking-tight">CrabDNS</h1>
            <p class="text-xs text-[#666666] dark:text-[#a1a1aa]">{t("authLoginSubtitle")}</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} class="space-y-4">
          <div>
            <label class="block text-xs font-medium mb-1.5">{t("authUsernameLabel")}</label>
            <input
              type="text"
              autocomplete="username"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
              required
            />
          </div>
          <div>
            <label class="block text-xs font-medium mb-1.5">{t("authPasswordLabel")}</label>
            <input
              type="password"
              autocomplete="current-password"
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
              class="w-full h-9 bg-[#fafafa] dark:bg-[#000000] border border-[#eaeaea] dark:border-[#262626] rounded-lg px-3 text-sm outline-none focus:border-[#171717] dark:focus:border-[#ededed]"
              required
            />
          </div>

          <Show when={error()}>
            <div class="rounded-lg border border-rose-500/20 bg-rose-500/10 text-rose-600 dark:text-rose-400 px-3 py-2 text-xs flex items-center gap-1.5">
              <span class="i-ri-error-warning-line shrink-0" />
              <span>{error()}</span>
            </div>
          </Show>

          <button
            type="submit"
            disabled={submitting()}
            class="w-full h-9 rounded-lg text-sm font-medium bg-[#171717] hover:bg-[#383838] dark:bg-[#ededed] dark:hover:bg-[#d4d4d8] text-white dark:text-[#0a0a0a] cursor-pointer border-0 transition-all active:scale-[0.98] disabled:opacity-50"
          >
            {submitting() ? t("authLoggingIn") : t("authLoginButton")}
          </button>
        </form>
      </div>
    </div>
  );
}
