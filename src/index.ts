import { OAuthClient } from './oauth';

interface Env {
	GITHUB_OAUTH_ID: string;
	GITHUB_OAUTH_SECRET: string;
  GITHUB_REPO_PRIVATE?: string;
  DECAP_CMS_ORIGIN?: string;
}

function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return Array.from(buf)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

const createOAuth = (env: Env) => {
	return new OAuthClient({
		id: env.GITHUB_OAUTH_ID,
		secret: env.GITHUB_OAUTH_SECRET,
		target: {
			tokenHost: 'https://github.com',
			tokenPath: '/login/oauth/access_token',
			authorizePath: '/login/oauth/authorize',
		},
	});
};

const getCmsOrigin = (request: Request) => {
	const referer = request.headers.get('Referer');
	if (!referer) {
		return undefined;
	}

	try {
		return new URL(referer).origin;
	} catch {
		return undefined;
	}
};

const handleAuth = async (request: Request, url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

  const repoIsPrivate = env.GITHUB_REPO_PRIVATE != undefined && env.GITHUB_REPO_PRIVATE !== '0';
  const repoScope = repoIsPrivate ? 'repo,user' : 'public_repo,user';

	const oauth2 = createOAuth(env);
	const redirectUri = new URL(`https://${url.hostname}/callback`);
	redirectUri.searchParams.set('provider', 'github');
	const cmsOrigin = getCmsOrigin(request) ?? env.DECAP_CMS_ORIGIN;
	if (cmsOrigin) {
		redirectUri.searchParams.set('origin', cmsOrigin);
	}

	const authorizationUri = oauth2.authorizeURL({
		redirect_uri: redirectUri.toString(),
		scope: repoScope,
		state: randomHex(4), // 4 bytes -> 8 hex chars
	});

	return new Response(null, { headers: { location: authorizationUri }, status: 301 });
};

const callbackScriptResponse = (status: string, token: string, targetOrigin: string) => {
	return new Response(
		`
<html>
<head>
  <script>
    const targetOrigin = ${JSON.stringify(targetOrigin)};

    const sendAuthorization = () => {
      window.opener.postMessage(
        'authorization:github:${status}:${JSON.stringify({ token })}',
        targetOrigin
      );
    };

    const receiveMessage = (message) => {
      sendAuthorization();
      window.removeEventListener("message", receiveMessage, false);
    }

    window.addEventListener("message", receiveMessage, false);
    window.opener.postMessage("authorizing:github", targetOrigin);
    sendAuthorization();

    // Decap may miss the first popup message while the admin window regains focus.
    let attempts = 0;
    const interval = window.setInterval(() => {
      sendAuthorization();
      attempts += 1;
      if (attempts >= 10) {
        window.clearInterval(interval);
      }
    }, 500);
  </script>
  <body>
    <p>Authorizing Decap...</p>
  </body>
</head>
</html>
`,
		{ headers: { 'Content-Type': 'text/html' } }
	);
};

const handleCallback = async (url: URL, env: Env) => {
	const provider = url.searchParams.get('provider');
	if (provider !== 'github') {
		return new Response('Invalid provider', { status: 400 });
	}

	const code = url.searchParams.get('code');
	if (!code) {
		return new Response('Missing code', { status: 400 });
	}

	const cmsOrigin = url.searchParams.get('origin') ?? env.DECAP_CMS_ORIGIN;
	if (!cmsOrigin) {
		return new Response('Missing CMS origin', { status: 400 });
	}

	const oauth2 = createOAuth(env);
	const accessToken = await oauth2.getToken({
		code,
		redirect_uri: `https://${url.hostname}/callback?provider=github&origin=${encodeURIComponent(cmsOrigin)}`,
	});
	return callbackScriptResponse('success', accessToken, cmsOrigin);
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);
    console.log(`url.pathname is ${url.pathname}`);
		if (url.pathname === '/auth') {
			return handleAuth(request, url, env);
		}
		if (url.pathname === '/callback') {
			return handleCallback(url, env);
		}
		return new Response('Hello 👋');
	},
};
