import {
  createHash,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import {
  chmod,
  mkdir,
  readFile,
  rename,
  writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER = 'https://auth.openai.com';
const AUTHORIZE_ENDPOINT =
  'https://auth.openai.com/api/accounts/authorize';
const TOKEN_ENDPOINT =
  'https://auth.openai.com/api/accounts/oauth/token';
const JWKS_URI =
  'https://auth.openai.com/.well-known/jwks.json';

const RESOURCE = 'https://api.openai.com/v1';

const SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'resource.invoke',
  'chatgpt.tokens.use.direct',
];

const AGENT_NAME = 'OpenDots';

const configDir =
  process.env.OPENDOTS_CHATGPT_CONFIG_DIR ??
  path.join(os.homedir(), '.config', 'opendots-chatgpt');

const hostFile = path.join(configDir, 'host.json');
const authFile = path.join(configDir, 'auth.json');

function randomBase64Url(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

async function writeJsonAtomic(file, value) {
  await mkdir(path.dirname(file), {
    recursive: true,
    mode: 0o700,
  });

  const temporary =
    `${file}.tmp-${process.pid}-${Date.now()}`;

  await writeFile(
    temporary,
    `${JSON.stringify(value, null, 2)}\n`,
    {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    },
  );

  await rename(temporary, file);
  await chmod(file, 0o600);
}

async function readJsonIfPresent(file) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return undefined;
    }

    throw error;
  }
}

async function getOrCreateHostId() {
  const existing = await readJsonIfPresent(hostFile);

  if (
    existing &&
    typeof existing.ext_agent_host_id === 'string'
  ) {
    return existing.ext_agent_host_id;
  }

  const extAgentHostId = `urn:uuid:${randomUUID()}`;

  await writeJsonAtomic(hostFile, {
    ext_agent_host_id: extAgentHostId,
    created_at: new Date().toISOString(),
  });

  return extAgentHostId;
}

function openBrowser(url) {
  const platform = process.platform;

  let command;
  let args;

  if (platform === 'darwin') {
    command = 'open';
    args = [url];
  } else if (platform === 'win32') {
    command = 'cmd';
    args = ['/c', 'start', '', url];
  } else {
    command = 'xdg-open';
    args = [url];
  }

  execFile(command, args, (error) => {
    if (error) {
      console.error(
        '\nCould not open the browser automatically.',
      );
      console.error('Open this URL manually:\n');
      console.error(url);
    }
  });
}

async function waitForCallback({
  state,
  currentClientId,
  isNewRegistration,
}) {
  return await new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      try {
        const requestUrl = new URL(
          req.url ?? '/',
          'http://127.0.0.1',
        );

        if (requestUrl.pathname !== '/auth/callback') {
          res.writeHead(404);
          res.end('Not found.');
          return;
        }

        const returnedState =
          requestUrl.searchParams.get('state');

        if (returnedState !== state) {
          res.writeHead(400, {
            'Content-Type': 'text/plain',
          });
          res.end('Invalid OAuth state.');
          reject(new Error('OAuth state mismatch.'));
          server.close();
          return;
        }

        const oauthError =
          requestUrl.searchParams.get('error');

        if (oauthError) {
          const description =
            requestUrl.searchParams.get(
              'error_description',
            );

          res.writeHead(400, {
            'Content-Type': 'text/plain',
          });

          res.end(
            `Authorization failed: ${oauthError}`,
          );

          reject(
            new Error(
              description
                ? `${oauthError}: ${description}`
                : oauthError,
            ),
          );

          server.close();
          return;
        }

        const code =
          requestUrl.searchParams.get('code');

        const returnedClientId =
          requestUrl.searchParams.get('client_id');

        if (!code) {
          throw new Error(
            'OAuth callback did not include an authorization code.',
          );
        }

        let issuedClientId;

        if (isNewRegistration) {
          if (!returnedClientId) {
            throw new Error(
              'New ChatGPT registration did not return an issued client_id.',
            );
          }

          issuedClientId = returnedClientId;
        } else {
          if (
            returnedClientId &&
            returnedClientId !== currentClientId
          ) {
            throw new Error(
              'ChatGPT returned a different client_id for an existing registration.',
            );
          }

          issuedClientId = currentClientId;
        }

        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
        });

        res.end(`
<!doctype html>
<html>
  <body style="font-family: sans-serif; padding: 40px;">
    <h2>OpenDots connected to ChatGPT</h2>
    <p>You can close this tab and return to Terminal.</p>
  </body>
</html>
        `);

        resolve({
          code,
          issuedClientId,
        });

        server.close();
      } catch (error) {
        res.writeHead(500, {
          'Content-Type': 'text/plain',
        });
        res.end('OAuth callback failed.');
        reject(error);
        server.close();
      }
    });

    server.on('error', reject);

    server.listen(0, '127.0.0.1', () => {
      resolve.listener = server;
    });
  });
}

async function createCallbackServer(state, currentClientId) {
  const isNewRegistration = !currentClientId;

  let resolveCallback;
  let rejectCallback;

  const callbackPromise = new Promise(
    (resolve, reject) => {
      resolveCallback = resolve;
      rejectCallback = reject;
    },
  );

  const server = createServer((req, res) => {
    try {
      const requestUrl = new URL(
        req.url ?? '/',
        'http://127.0.0.1',
      );

      if (requestUrl.pathname !== '/auth/callback') {
        res.writeHead(404);
        res.end('Not found.');
        return;
      }

      const returnedState =
        requestUrl.searchParams.get('state');

      if (returnedState !== state) {
        throw new Error('OAuth state mismatch.');
      }

      const oauthError =
        requestUrl.searchParams.get('error');

      if (oauthError) {
        const description =
          requestUrl.searchParams.get(
            'error_description',
          );

        throw new Error(
          description
            ? `${oauthError}: ${description}`
            : oauthError,
        );
      }

      const code =
        requestUrl.searchParams.get('code');

      if (!code) {
        throw new Error(
          'OAuth callback did not include an authorization code.',
        );
      }

      const returnedClientId =
        requestUrl.searchParams.get('client_id');

      let issuedClientId;

      if (isNewRegistration) {
        if (!returnedClientId) {
          throw new Error(
            'New registration did not return an issued client_id.',
          );
        }

        issuedClientId = returnedClientId;
      } else {
        if (
          returnedClientId &&
          returnedClientId !== currentClientId
        ) {
          throw new Error(
            'OAuth callback returned an unexpected client_id.',
          );
        }

        issuedClientId = currentClientId;
      }

      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
      });

      res.end(`
<!doctype html>
<html>
  <body style="font-family: sans-serif; padding: 40px;">
    <h2>OpenDots connected to ChatGPT</h2>
    <p>You can close this tab and return to Terminal.</p>
  </body>
</html>
      `);

      resolveCallback({
        code,
        issuedClientId,
      });

      server.close();
    } catch (error) {
      res.writeHead(400, {
        'Content-Type': 'text/plain; charset=utf-8',
      });

      res.end(
        error instanceof Error
          ? error.message
          : 'OAuth callback failed.',
      );

      rejectCallback(error);
      server.close();
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);

    server.listen(0, '127.0.0.1', () => {
      resolve();
    });
  });

  const address = server.address();

  if (!address || typeof address === 'string') {
    server.close();
    throw new Error(
      'Could not determine OAuth callback port.',
    );
  }

  return {
    server,
    callbackPromise,
    redirectUri:
      `http://127.0.0.1:${address.port}/auth/callback`,
  };
}

async function exchangeCode({
  code,
  clientId,
  codeVerifier,
  redirectUri,
}) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    code_verifier: codeVerifier,
    redirect_uri: redirectUri,
    resource: RESOURCE,
  });

  const response = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type':
        'application/x-www-form-urlencoded',
    },
    body,
  });

  const text = await response.text();

  let result;

  try {
    result = JSON.parse(text);
  } catch {
    throw new Error(
      `OpenAI token endpoint returned HTTP ${response.status} with invalid JSON.`,
    );
  }

  if (!response.ok) {
    throw new Error(
      result.error_description ??
      result.error ??
      `Token exchange failed with HTTP ${response.status}`,
    );
  }

  return result;
}

async function main() {
  await mkdir(configDir, {
    recursive: true,
    mode: 0o700,
  });

  const extAgentHostId =
    await getOrCreateHostId();

  const existing =
    await readJsonIfPresent(authFile);

  const state = randomBase64Url();
  const nonce = randomBase64Url();
  const codeVerifier = randomBase64Url(64);

  const codeChallenge = createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  const existingClientId =
    typeof existing?.client_id === 'string'
      ? existing.client_id
      : undefined;

  const {
    server,
    callbackPromise,
    redirectUri,
  } = await createCallbackServer(
    state,
    existingClientId,
  );

  const clientId =
    existingClientId ??
    'dynamic_agent_client';

  const authorizationUrl =
    new URL(AUTHORIZE_ENDPOINT);

  authorizationUrl.searchParams.set(
    'client_id',
    clientId,
  );

  authorizationUrl.searchParams.set(
    'response_type',
    'code',
  );

  authorizationUrl.searchParams.set(
    'redirect_uri',
    redirectUri,
  );

  authorizationUrl.searchParams.set(
    'scope',
    SCOPES.join(' '),
  );

  authorizationUrl.searchParams.set(
    'resource',
    RESOURCE,
  );

  authorizationUrl.searchParams.set(
    'state',
    state,
  );

  authorizationUrl.searchParams.set(
    'nonce',
    nonce,
  );

  authorizationUrl.searchParams.set(
    'code_challenge_method',
    'S256',
  );

  authorizationUrl.searchParams.set(
    'code_challenge',
    codeChallenge,
  );

  authorizationUrl.searchParams.set(
    'ext_agent_host_id',
    extAgentHostId,
  );

  if (!existingClientId) {
    authorizationUrl.searchParams.set(
      'agent_name_hint',
      AGENT_NAME,
    );
  } else {
    if (typeof existing?.id_token === 'string') {
      authorizationUrl.searchParams.set(
        'id_token_hint',
        existing.id_token,
      );
    }

    if (typeof existing?.email === 'string') {
      authorizationUrl.searchParams.set(
        'login_hint',
        existing.email,
      );
    }
  }

  console.log('\nOpening Continue with ChatGPT...\n');
  console.log(
    `Callback: ${redirectUri}`,
  );

  openBrowser(authorizationUrl.toString());

  let callback;

  try {
    callback = await callbackPromise;
  } finally {
    server.close();
  }

  const tokens = await exchangeCode({
    code: callback.code,
    clientId: callback.issuedClientId,
    codeVerifier,
    redirectUri,
  });

  if (
    typeof tokens.id_token !== 'string' ||
    typeof tokens.access_token !== 'string' ||
    typeof tokens.refresh_token !== 'string'
  ) {
    throw new Error(
      'OpenAI did not return the required OAuth credentials.',
    );
  }

  const jwks =
    createRemoteJWKSet(new URL(JWKS_URI));

  const { payload } = await jwtVerify(
    tokens.id_token,
    jwks,
    {
      issuer: ISSUER,
      audience: callback.issuedClientId,
    },
  );

  if (payload.nonce !== nonce) {
    throw new Error(
      'OpenAI ID token nonce did not match the authorization request.',
    );
  }

  if (typeof payload.sub !== 'string') {
    throw new Error(
      'OpenAI ID token does not contain a valid subject.',
    );
  }

  if (
    existing?.subject &&
    existing.subject !== payload.sub
  ) {
    throw new Error(
      'The authorized ChatGPT account does not match the existing registration.',
    );
  }

  const scopes =
    typeof tokens.scope === 'string'
      ? tokens.scope.split(/\s+/).filter(Boolean)
      : [];

  if (
    !scopes.includes(
      'chatgpt.tokens.use.direct',
    )
  ) {
    throw new Error(
      'ChatGPT plan usage permission was not granted.',
    );
  }

  const credentials = {
    email:
      typeof payload.email === 'string'
        ? payload.email
        : undefined,

    issuer: ISSUER,
    subject: payload.sub,
    client_id: callback.issuedClientId,
    ext_agent_host_id: extAgentHostId,

    id_token: tokens.id_token,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,

    token_type:
      typeof tokens.token_type === 'string'
        ? tokens.token_type
        : 'Bearer',

    expires_in:
      typeof tokens.expires_in === 'number'
        ? tokens.expires_in
        : 3600,

    earliest_refresh_at:
      tokens.earliest_refresh_at,

    scopes,
    saved_at: new Date().toISOString(),
  };

  await writeJsonAtomic(
    authFile,
    credentials,
  );

  console.log('\nChatGPT authorization successful.');
  console.log(`Credentials: ${authFile}`);
  console.log(`VM host ID:    ${hostFile}`);

  if (credentials.email) {
    console.log(
      `Account:       ${credentials.email}`,
    );
  }

  console.log(
    '\nDo not commit or paste either credential file into chat.',
  );
}

main().catch((error) => {
  console.error('\nChatGPT authorization failed.');

  if (error instanceof Error) {
    console.error(error.message);
  } else {
    console.error(error);
  }

  process.exitCode = 1;
});
