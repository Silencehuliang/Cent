// GitHub OAuth 回调：校验 state 后用 code 换取 access_token，
// 再把 token 带回前端（前端 index.html 内联脚本读取 github_authorized 参数）。
// 需要的环境变量：GITHUB_CLIENT_ID、GITHUB_CLIENT_SECRET。

type Env = {
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
};

const STATE_TTL_MS = 10 * 60 * 1000;

const toBase64Url = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

const signState = async (payload: string, secret: string) => {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
    );
    const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(payload),
    );
    return `${payload}.${toBase64Url(new Uint8Array(signature))}`;
};

export const onRequestGet = async ({
    request,
    env,
}: {
    request: Request;
    env: Env;
}) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") ?? "";
    const secret = env.GITHUB_CLIENT_SECRET;
    if (!env.GITHUB_CLIENT_ID || !secret) {
        return new Response("GitHub OAuth is not configured.", { status: 500 });
    }
    if (!code) {
        return new Response("Missing code.", { status: 400 });
    }
    const index = state.lastIndexOf(".");
    const payload = state.slice(0, index);
    const issuedAt = Number(payload.split(".")[0]);
    const valid =
        index > 0 &&
        Number.isFinite(issuedAt) &&
        Date.now() - issuedAt <= STATE_TTL_MS &&
        (await signState(payload, secret)) === state;
    if (!valid) {
        return new Response("Invalid state.", { status: 400 });
    }
    const tokenResponse = await fetch(
        "https://github.com/login/oauth/access_token",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({
                client_id: env.GITHUB_CLIENT_ID,
                client_secret: secret,
                code,
            }),
        },
    );
    const tokenData = (await tokenResponse.json()) as {
        access_token?: string;
        error?: string;
        error_description?: string;
    };
    if (!tokenData.access_token) {
        return new Response(
            `GitHub OAuth failed: ${tokenData.error_description ?? tokenData.error ?? "unknown error"}`,
            { status: 400 },
        );
    }
    const back = new URL("/", url.origin);
    back.searchParams.set("github_authorized", JSON.stringify(tokenData));
    return Response.redirect(back.toString(), 302);
};
