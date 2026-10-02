// 自托管的 GitHub OAuth 入口。
// 不依赖任何外部后端：校验回调域名后，携带签名 state 跳转到 GitHub 授权页。
// 需要的环境变量：GITHUB_CLIENT_ID、GITHUB_CLIENT_SECRET。

type Env = {
    GITHUB_CLIENT_ID?: string;
    GITHUB_CLIENT_SECRET?: string;
};

const toBase64Url = (bytes: Uint8Array) =>
    btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

const buildState = async (secret: string) => {
    const payload = `${Date.now()}.${crypto.randomUUID()}`;
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
    const requested = url.searchParams.get("redirect_uri") ?? url.origin;
    let redirectOrigin: string;
    try {
        redirectOrigin = new URL(requested).origin;
    } catch {
        return new Response("Invalid redirect_uri.", { status: 400 });
    }
    if (redirectOrigin !== url.origin) {
        return new Response("redirect_uri must be same-origin.", {
            status: 400,
        });
    }
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
        return new Response("GitHub OAuth is not configured.", { status: 500 });
    }
    const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
    authorizeUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    // 不传 redirect_uri：回调地址用 OAuth App 里登记的那一个，
    // 这样多个访问域名（pages.dev / 自定义域名）始终回到同一处完成换 token。
    authorizeUrl.searchParams.set("scope", "repo");
    authorizeUrl.searchParams.set(
        "state",
        await buildState(env.GITHUB_CLIENT_SECRET),
    );
    return Response.redirect(authorizeUrl.toString(), 302);
};
