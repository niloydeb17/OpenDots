import { mkdir, chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const TOKEN_ENDPOINT =
  'https://auth.openai.com/api/accounts/oauth/token';

const RESOURCE = 'https://api.openai.com/v1';
const REQUIRED_SCOPE = 'chatgpt.tokens.use.direct';

// Refresh five minutes before normal expiry.
const REFRESH_EARLY_MS = 5 * 60 * 1000;

export interface ChatGptCredentials {
  email?: string;
  issuer: string;
  subject: string;
  client_id: string;
  ext_agent_host_id?: string;

  id_token: string;
  access_token: string;
  refresh_token: string;
  token_type: string;

  expires_in: number;
  earliest_refresh_at?: number | string;
  scopes: string[];
  saved_at: string;
}

interface RefreshResponse {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
  earliest_refresh_at?: number | string;
  scope?: string;
  error?: string;
  error_description?: string;
}

let refreshInFlight: Promise<ChatGptCredentials> | undefined;

function assertCredentials(
  value: unknown,
  source: string,
): ChatGptCredentials {
  if (!value || typeof value !== 'object') {
    throw new Error(`Invalid ChatGPT credential file: ${source}`);
  }

  const credentials = value as Partial<ChatGptCredentials>;

  const required: Array<keyof ChatGptCredentials> = [
    'issuer',
    'subject',
    'client_id',
    'id_token',
    'access_token',
    'refresh_token',
    'token_type',
    'expires_in',
    'scopes',
    'saved_at',
  ];

  for (const key of required) {
    if (credentials[key] === undefined || credentials[key] === null) {
      throw new Error(
        `ChatGPT credential file is missing ${String(key)}.`,
      );
    }
  }

  if (
    !Array.isArray(credentials.scopes) ||
    !credentials.scopes.includes(REQUIRED_SCOPE)
  ) {
    throw new Error(
      `ChatGPT credentials do not include ${REQUIRED_SCOPE}.`,
    );
  }

  if (credentials.issuer !== 'https://auth.openai.com') {
    throw new Error('Unexpected ChatGPT credential issuer.');
  }

  return credentials as ChatGptCredentials;
}

export async function readChatGptCredentials(
  file: string,
): Promise<ChatGptCredentials> {
  let raw: string;

  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    const code =
      error &&
      typeof error === 'object' &&
      'code' in error
        ? String(error.code)
        : undefined;

    if (code === 'ENOENT') {
      throw new Error(
        `ChatGPT credentials were not found at ${file}. Run the ChatGPT login/import flow first.`,
        { cause: error },
      );
    }

    throw error;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `ChatGPT credential file is not valid JSON: ${file}`,
      { cause: error },
    );
  }

  return assertCredentials(parsed, file);
}

async function writeCredentialsAtomic(
  file: string,
  credentials: ChatGptCredentials,
): Promise<void> {
  const directory = dirname(file);
  await mkdir(directory, { recursive: true, mode: 0o700 });

  const temporary = `${file}.tmp-${process.pid}-${Date.now()}`;

  await writeFile(
    temporary,
    `${JSON.stringify(credentials, null, 2)}\n`,
    {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    },
  );

  await rename(temporary, file);
  await chmod(file, 0o600);
}

function savedAtMs(credentials: ChatGptCredentials): number {
  const value = Date.parse(credentials.saved_at);

  if (!Number.isFinite(value)) {
    throw new Error('ChatGPT credentials contain an invalid saved_at value.');
  }

  return value;
}

function earliestRefreshMs(
  credentials: ChatGptCredentials,
): number | undefined {
  const value = credentials.earliest_refresh_at;

  if (value === undefined) return undefined;

  if (typeof value === 'number') {
    // OAuth timestamps are normally Unix seconds.
    return value > 10_000_000_000 ? value : value * 1000;
  }

  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return numeric > 10_000_000_000 ? numeric : numeric * 1000;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function shouldRefresh(credentials: ChatGptCredentials): boolean {
  const expiresAt =
    savedAtMs(credentials) + credentials.expires_in * 1000;

  return Date.now() >= expiresAt - REFRESH_EARLY_MS;
}

async function refreshCredentials(
  file: string,
  current: ChatGptCredentials,
): Promise<ChatGptCredentials> {
  const earliest = earliestRefreshMs(current);
  const expiresAt =
    savedAtMs(current) + current.expires_in * 1000;

  if (earliest && Date.now() < earliest) {
    if (Date.now() < expiresAt) {
      return current;
    }

    throw new Error(
      'ChatGPT access token expired before its allowed refresh time.',
    );
  }

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: current.client_id,
    refresh_token: current.refresh_token,
    resource: RESOURCE,
  });

  const response = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  let result: RefreshResponse;

  try {
    result = (await response.json()) as RefreshResponse;
  } catch {
    throw new Error(
      `ChatGPT token refresh returned HTTP ${response.status} with an invalid response.`,
    );
  }

  if (!response.ok) {
    const detail =
      result.error_description ??
      result.error ??
      `HTTP ${response.status}`;

    throw new Error(`ChatGPT token refresh failed: ${detail}`);
  }

  if (!result.access_token || !result.refresh_token) {
    throw new Error(
      'ChatGPT token refresh did not return replacement credentials.',
    );
  }

  const scopes = result.scope
    ? result.scope.split(/\s+/).filter(Boolean)
    : current.scopes;

  if (!scopes.includes(REQUIRED_SCOPE)) {
    throw new Error(
      `Refreshed ChatGPT credentials lost ${REQUIRED_SCOPE}.`,
    );
  }

  const updated: ChatGptCredentials = {
    ...current,
    access_token: result.access_token,
    refresh_token: result.refresh_token,
    id_token: result.id_token ?? current.id_token,
    token_type: result.token_type ?? current.token_type,
    expires_in: result.expires_in ?? current.expires_in,
    earliest_refresh_at:
      result.earliest_refresh_at ?? current.earliest_refresh_at,
    scopes,
    saved_at: new Date().toISOString(),
  };

  await writeCredentialsAtomic(file, updated);

  return updated;
}

export async function getChatGptAccessToken(
  file: string,
): Promise<string> {
  const current = await readChatGptCredentials(file);

  if (!shouldRefresh(current)) {
    return current.access_token;
  }

  // Refresh tokens rotate, so never allow concurrent refreshes in this process.
  refreshInFlight ??= refreshCredentials(file, current).finally(() => {
    refreshInFlight = undefined;
  });

  const refreshed = await refreshInFlight;
  return refreshed.access_token;
}

export function createChatGptAccessTokenProvider(
  file: string,
): () => Promise<string> {
  return () => getChatGptAccessToken(file);
}
