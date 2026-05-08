const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const axios = require('axios');

const AUTHORIZE_URL = 'https://auth.atlassian.com/authorize';
const TOKEN_URL = 'https://auth.atlassian.com/oauth/token';
const ACCESSIBLE_RESOURCES_URL = 'https://api.atlassian.com/oauth/token/accessible-resources';

const DEFAULT_OAUTH_SCOPES = [
  // Classic scopes cover the REST v1 endpoints used by most CLI commands.
  'read:confluence-content.all',
  'read:confluence-content.summary',
  'read:confluence-space.summary',
  'search:confluence',
  'read:confluence-user',
  'read:confluence-props',
  'write:confluence-props',
  'write:confluence-content',
  'write:confluence-file',
  'readonly:content.attachment:confluence',

  // Granular scopes cover Cloud REST v2 ADF operations and newer content types.
  'read:page:confluence',
  'write:page:confluence',
  'delete:page:confluence',
  'read:comment:confluence',
  'write:comment:confluence',
  'delete:comment:confluence',
  'read:folder:confluence',
  'write:folder:confluence',
  'delete:folder:confluence',
  'read:space:confluence',
  'read:content-details:confluence',
  'read:hierarchical-content:confluence',
  'read:attachment:confluence',
  'write:attachment:confluence',
  'delete:attachment:confluence',
  'read:content.property:confluence',
  'write:content.property:confluence',
  'read:user:confluence',

  // Required to refresh OAuth tokens without asking the user to log in again.
  'offline_access'
];

function parseScopes(value) {
  if (Array.isArray(value)) {
    return value.map(String).map(scope => scope.trim()).filter(Boolean);
  }
  if (!value) {
    return [...DEFAULT_OAUTH_SCOPES];
  }
  return String(value)
    .split(/[,\s]+/)
    .map(scope => scope.trim())
    .filter(Boolean);
}

function normalizeSiteUrl(value) {
  if (!value) {
    return null;
  }
  const raw = String(value).trim();
  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const parsed = new URL(withProtocol);
  return parsed.origin;
}

function siteDomain(value) {
  const siteUrl = normalizeSiteUrl(value);
  return siteUrl ? new URL(siteUrl).hostname : null;
}

function randomState() {
  return crypto.randomBytes(24).toString('hex');
}

function buildAuthorizeUrl({ clientId, redirectUri, scopes, state, prompt = 'consent' }) {
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('audience', 'api.atlassian.com');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('scope', parseScopes(scopes).join(' '));
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('prompt', prompt);
  return url.toString();
}

async function exchangeAuthorizationCode({ clientId, clientSecret, code, redirectUri }) {
  const response = await axios.post(TOKEN_URL, {
    grant_type: 'authorization_code',
    client_id: clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: redirectUri
  }, {
    headers: { 'Content-Type': 'application/json' }
  });
  return response.data;
}

async function refreshAccessToken({ clientId, clientSecret, refreshToken }) {
  const response = await axios.post(TOKEN_URL, {
    grant_type: 'refresh_token',
    client_id: clientId,
    client_secret: clientSecret,
    refresh_token: refreshToken
  }, {
    headers: { 'Content-Type': 'application/json' }
  });
  return response.data;
}

async function getAccessibleResources(accessToken) {
  const response = await axios.get(ACCESSIBLE_RESOURCES_URL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json'
    }
  });
  return Array.isArray(response.data) ? response.data : [];
}

function findResourceForSite(resources, targetSite) {
  const targetUrl = normalizeSiteUrl(targetSite);
  if (!targetUrl) {
    return null;
  }
  return resources.find(resource => normalizeSiteUrl(resource.url) === targetUrl) || null;
}

function openBrowser(url) {
  const command = process.platform === 'darwin'
    ? 'open'
    : (process.platform === 'win32' ? 'cmd' : 'xdg-open');
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  const child = spawn(command, args, { detached: true, stdio: 'ignore' });
  child.unref();
}

function waitForOAuthCallback(redirectUri, expectedState, timeoutMs = 300000) {
  const parsed = new URL(redirectUri);
  if (!['127.0.0.1', 'localhost'].includes(parsed.hostname) || !parsed.port) {
    throw new Error('Automatic OAuth callback capture requires a localhost redirect URI with an explicit port.');
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error('Timed out waiting for OAuth callback.'));
    }, timeoutMs);

    const server = http.createServer((req, res) => {
      const requestUrl = new URL(req.url, redirectUri);
      if (requestUrl.pathname !== parsed.pathname) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const state = requestUrl.searchParams.get('state');
      const code = requestUrl.searchParams.get('code');
      const error = requestUrl.searchParams.get('error');

      if (error) {
        clearTimeout(timeout);
        server.close();
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('OAuth authorization failed. You can close this window.');
        reject(new Error(`OAuth authorization failed: ${error}`));
        return;
      }

      if (state !== expectedState) {
        clearTimeout(timeout);
        server.close();
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Invalid OAuth state. You can close this window.');
        reject(new Error('OAuth callback state did not match the expected value.'));
        return;
      }

      if (!code) {
        clearTimeout(timeout);
        server.close();
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing OAuth code. You can close this window.');
        reject(new Error('OAuth callback did not include an authorization code.'));
        return;
      }

      clearTimeout(timeout);
      server.close();
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Confluence CLI OAuth login complete. You can close this window.');
      resolve({ code, state });
    });

    server.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    server.listen(Number(parsed.port), parsed.hostname);
  });
}

function codeFromCallbackUrl(callbackUrl, expectedState = null) {
  const parsed = new URL(callbackUrl);
  const state = parsed.searchParams.get('state');
  if (expectedState && state !== expectedState) {
    throw new Error('OAuth callback state did not match the expected value.');
  }
  const code = parsed.searchParams.get('code');
  if (!code) {
    throw new Error('OAuth callback URL did not include a code parameter.');
  }
  return code;
}

module.exports = {
  AUTHORIZE_URL,
  TOKEN_URL,
  ACCESSIBLE_RESOURCES_URL,
  DEFAULT_OAUTH_SCOPES,
  parseScopes,
  normalizeSiteUrl,
  siteDomain,
  randomState,
  buildAuthorizeUrl,
  exchangeAuthorizationCode,
  refreshAccessToken,
  getAccessibleResources,
  findResourceForSite,
  openBrowser,
  waitForOAuthCallback,
  codeFromCallbackUrl
};
