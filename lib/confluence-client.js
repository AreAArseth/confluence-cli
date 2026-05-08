const axios = require('axios');
const fs = require('fs');
const https = require('https');
const path = require('path');
const FormData = require('form-data');
const { convert } = require('html-to-text');
const MacroConverter = require('./macro-converter');
const { htmlToMarkdown, NAMED_ENTITIES } = require('./html-to-markdown');
const { refreshAccessToken } = require('./oauth');
const { updateOAuthTokens, normalizeOAuthConfig } = require('./config');

function createSemaphore(limit) {
  let active = 0;
  const waiters = [];
  return {
    async acquire() {
      if (active < limit) {
        active++;
        return;
      }
      await new Promise(resolve => waiters.push(resolve));
    },
    release() {
      if (waiters.length > 0) {
        const next = waiters.shift();
        next();
      } else {
        active--;
      }
    }
  };
}

class ConfluenceClient {
  constructor(config) {
    this.domain = config.domain;
    const rawProtocol = (config.protocol || 'https').trim().toLowerCase();
    this.protocol = (rawProtocol === 'http' || rawProtocol === 'https') ? rawProtocol : 'https';
    this.token = config.token;
    this.email = config.email;
    this.cookie = config.cookie;
    this.authType = (config.authType || (this.email ? 'basic' : 'bearer')).toLowerCase();
    this.oauth = normalizeOAuthConfig(config.oauth || config);
    this.profileName = config.profileName;
    this.forceCloud = !!config.forceCloud;
    this.mtls = config.mtls;
    this.apiPath = this.sanitizeApiPath(config.apiPath);
    this.webUrlPrefix = this.apiPath.includes('/wiki/') ? '/wiki' : '';
    this.browserOrigin = this.oauth?.siteUrl || `${this.protocol}://${this.domain}`;
    this.baseURL = this.authType === 'oauth' && this.oauth?.cloudId
      ? `https://api.atlassian.com/ex/confluence/${this.oauth.cloudId}${this.apiPath}`
      : `${this.protocol}://${this.domain}${this.apiPath}`;
    this.converter = new MacroConverter({
      isCloud: this.isCloud(),
      webUrlPrefix: this.webUrlPrefix,
      buildUrl: (pathOrUrl) => this.buildUrl(pathOrUrl),
      linkStyle: config.linkStyle,
    });
    this.markdown = this.converter.markdown;

    const headers = {
      'Content-Type': 'application/json',
      ...this.buildAuthHeaders()
    };

    const clientOptions = {
      baseURL: this.baseURL,
      headers
    };
    const httpsAgent = this.buildHttpsAgent();
    if (httpsAgent) {
      clientOptions.httpsAgent = httpsAgent;
    }

    this.client = axios.create(clientOptions);

    this.client.interceptors.request.use(async (requestConfig) => {
      if (this.authType === 'oauth') {
        const token = await this.getOAuthAccessToken();
        requestConfig.headers = requestConfig.headers || {};
        requestConfig.headers.Authorization = `Bearer ${token}`;
      }
      return requestConfig;
    });

    this.client.interceptors.response.use(
      response => response,
      async error => {
        if (this.authType === 'oauth' && error.response?.status === 401 && !error.config?._oauthRetry && this.oauth?.refreshToken) {
          try {
            await this.refreshOAuthAccessToken(true);
            error.config._oauthRetry = true;
            return this.client.request(error.config);
          } catch (refreshError) {
            error.message = `OAuth token refresh failed after 401 response: ${refreshError.message}`;
          }
        }
        if (error.response?.status === 401) {
          const hints = ['Authentication failed (401 Unauthorized).'];
          if (this.isScopedToken()) {
            hints.push(
              'You are using a scoped API token (api.atlassian.com). Please verify:',
              '  - Your token has the required scopes (e.g., read:confluence-content.all, read:confluence-content.summary, read:confluence-space.summary)',
              '  - Your Cloud ID in the API path is correct',
              '  - Your email matches the account that created the token',
              'See: https://developer.atlassian.com/cloud/confluence/scopes-for-oauth-2-3LO-and-forge-apps/'
            );
          } else if (this.authType === 'basic' && this.isCloud()) {
            hints.push(
              'Please verify your email and API token are correct.',
              'Generate a token at: https://id.atlassian.com/manage-profile/security/api-tokens'
            );
          } else if (this.authType === 'basic') {
            hints.push(
              'Please verify your username and password are correct.'
            );
          } else if (this.authType === 'mtls') {
            hints.push(
              'Please verify your client certificate, client key, and CA certificate are correct and trusted by the server.'
            );
          } else if (this.authType === 'cookie') {
            hints.push(
              'Please verify your cookie is valid and not expired.',
              'You may need to re-authenticate through your Enterprise SSO to get a fresh cookie.'
            );
          } else {
            hints.push(
              'Please verify your personal access token is valid and not expired.'
            );
          }
          error.message = hints.join('\n');
        }
        return Promise.reject(error);
      }
    );
  }

  isCloud() {
    return this.isScopedToken() || (this.domain && this.domain.trim().toLowerCase().endsWith('.atlassian.net')) || this.forceCloud;
  }

  isScopedToken() {
    const d = (this.domain || '').trim().toLowerCase();
    return d === 'api.atlassian.com' || this.apiPath?.includes('/ex/confluence/');
  }

  sanitizeApiPath(rawPath) {
    const fallback = '/rest/api';
    const value = (rawPath || '').trim();

    if (!value) {
      return fallback;
    }

    const withoutLeading = value.replace(/^\/+/, '');
    const normalized = `/${withoutLeading}`.replace(/\/+$/, '');
    return normalized || fallback;
  }

  buildBasicAuthHeader() {
    if (!this.email) {
      throw new Error('Basic authentication requires an email address or username.');
    }

    const encodedCredentials = Buffer.from(`${this.email}:${this.token}`).toString('base64');
    return `Basic ${encodedCredentials}`;
  }

  buildAuthHeader() {
    if (this.authType === 'mtls' || this.authType === 'cookie' || this.authType === 'oauth') {
      return null;
    }

    if (!this.token) {
      throw new Error(`Authentication type "${this.authType}" requires a token or password.`);
    }

    return this.authType === 'basic' ? this.buildBasicAuthHeader() : `Bearer ${this.token}`;
  }

  oauthExpiresSoon() {
    if (!this.oauth?.expiresAt) {
      return false;
    }
    return Number(this.oauth.expiresAt) <= Date.now() + 60000;
  }

  async getOAuthAccessToken() {
    if (!this.oauth) {
      throw new Error('OAuth authentication is not configured.');
    }
    if ((!this.oauth.accessToken || this.oauthExpiresSoon()) && this.oauth.refreshToken) {
      await this.refreshOAuthAccessToken();
    }
    if (!this.oauth.accessToken) {
      throw new Error('OAuth authentication requires an access token. Run "confluence oauth-login" or set CONFLUENCE_OAUTH_ACCESS_TOKEN.');
    }
    return this.oauth.accessToken;
  }

  async refreshOAuthAccessToken(force = false) {
    if (!this.oauth?.refreshToken) {
      throw new Error('OAuth refresh requires a refresh token.');
    }
    if (!force && this.oauth.accessToken && !this.oauthExpiresSoon()) {
      return this.oauth.accessToken;
    }
    if (!this.oauth.clientId || !this.oauth.clientSecret) {
      throw new Error('OAuth refresh requires a client ID and client secret.');
    }

    const tokenData = await refreshAccessToken({
      clientId: this.oauth.clientId,
      clientSecret: this.oauth.clientSecret,
      refreshToken: this.oauth.refreshToken
    });
    this.applyOAuthTokenData(tokenData);
    return this.oauth.accessToken;
  }

  applyOAuthTokenData(tokenData) {
    const expiresAt = tokenData.expires_in
      ? Date.now() + (Number(tokenData.expires_in) * 1000)
      : this.oauth.expiresAt;
    this.oauth = {
      ...this.oauth,
      accessToken: tokenData.access_token || this.oauth.accessToken,
      refreshToken: tokenData.refresh_token || this.oauth.refreshToken,
      expiresAt,
      scopes: tokenData.scope ? tokenData.scope.split(/\s+/).filter(Boolean) : this.oauth.scopes
    };
    updateOAuthTokens(this.profileName, this.oauth);
  }

  buildAuthHeaders() {
    const headers = {};
    const authHeader = this.buildAuthHeader();
    if (authHeader) {
      headers.Authorization = authHeader;
    }
    if (this.authType === 'cookie' && this.cookie) {
      headers.Cookie = this.cookie;
    }
    return headers;
  }

  buildHttpsAgent() {
    if (this.protocol !== 'https' || !this.mtls) {
      return null;
    }

    const options = {};

    if (this.mtls.caCert) {
      if (!fs.existsSync(this.mtls.caCert)) {
        throw new Error(`CA certificate file not found: ${this.mtls.caCert}`);
      }
      options.ca = fs.readFileSync(this.mtls.caCert);
    }
    if (this.mtls.clientCert) {
      if (!fs.existsSync(this.mtls.clientCert)) {
        throw new Error(`Client certificate file not found: ${this.mtls.clientCert}`);
      }
      options.cert = fs.readFileSync(this.mtls.clientCert);
    }
    if (this.mtls.clientKey) {
      if (!fs.existsSync(this.mtls.clientKey)) {
        throw new Error(`Client key file not found: ${this.mtls.clientKey}`);
      }
      // Warn if private key file is readable by others (Unix only)
      if (process.platform !== 'win32') {
        try {
          const keyStats = fs.statSync(this.mtls.clientKey);
          const keyMode = keyStats.mode & 0o777;
          if (keyMode & 0o077) {
            console.error(
              `Warning: Client key file "${this.mtls.clientKey}" has mode ${keyMode.toString(8)}. ` +
              'Private keys should not be readable by other users (recommended: 0600). ' +
              `Fix with: chmod 600 "${this.mtls.clientKey}"`
            );
          }
        } catch {
          // Ignore stat errors — the read below will surface them
        }
      }
      options.key = fs.readFileSync(this.mtls.clientKey);
    }

    if (Object.keys(options).length === 0) {
      return null;
    }

    return new https.Agent(options);
  }

  /**
   * Extract page ID from URL or return the ID if it's already a number
   */
  async extractPageId(pageIdOrUrl) {
    if (typeof pageIdOrUrl === 'number' || /^\d+$/.test(pageIdOrUrl)) {
      return pageIdOrUrl;
    }

    // Check if it's a Confluence URL
    if (pageIdOrUrl.includes(this.domain)) {
      // Extract pageId from URL parameter
      const pageIdMatch = pageIdOrUrl.match(/pageId=(\d+)/);
      if (pageIdMatch) {
        return pageIdMatch[1];
      }

      const prettyMatch = pageIdOrUrl.match(/\/pages\/(\d+)(?:[/?#]|$)/);
      if (prettyMatch) {
        return prettyMatch[1];
      }

      // Handle tiny links (/wiki/x/<code>)
      const tinyLinkMatch = pageIdOrUrl.match(/\/wiki\/x\/([A-Za-z0-9_-]+)/);
      if (tinyLinkMatch) {
        try {
          const response = await this.client.get(pageIdOrUrl, {
            maxRedirects: 0,
            validateStatus: (status) => status >= 300 && status < 400
          });
          const redirectUrl = response.headers.location;
          if (redirectUrl) {
            return this.extractPageId(redirectUrl);
          }
        } catch (error) {
          if (error.response && error.response.headers && error.response.headers.location) {
            return this.extractPageId(error.response.headers.location);
          }
        }
        throw new Error(`Could not resolve page ID from tiny link: ${pageIdOrUrl}`);
      }

      // Handle display URLs - search by space and title
      const displayMatch = pageIdOrUrl.match(/\/display\/([^/]+)\/(.+)/);
      if (displayMatch) {
        const spaceKey = displayMatch[1];
        // Confluence friendly URLs for child pages might look like /display/SPACE/Parent/Child
        // We only want the last part as the title
        const urlPath = displayMatch[2];
        const lastSegment = urlPath.split('/').pop();

        // Confluence uses + for spaces in URL titles, but decodeURIComponent doesn't convert + to space
        const rawTitle = lastSegment.replace(/\+/g, '%20');
        const title = decodeURIComponent(rawTitle);

        try {
          if (this.shouldUseCloudV2PageApi()) {
            const pageInfo = await this.findPageByTitle(title, spaceKey);
            return pageInfo.id;
          }

          const response = await this.client.get('/content', {
            params: {
              spaceKey: spaceKey,
              title: title,
              limit: 1
            }
          });

          if (response.data.results && response.data.results.length > 0) {
            return response.data.results[0].id;
          }
        } catch (error) {
          // Ignore error and fall through
          console.error('Error resolving page ID from display URL:', error);
        }

        throw new Error(`Could not resolve page ID from display URL: ${pageIdOrUrl}`);
      }
    }

    return pageIdOrUrl;
  }

  /**
   * Extract referenced attachment filenames from HTML content
   * @param {string} htmlContent - HTML content in storage format
   * @returns {Set<string>} Set of referenced attachment filenames
   */
  extractReferencedAttachments(htmlContent) {
    const referenced = new Set();
    
    // Extract from ac:image with ri:attachment
    const imageRegex = /<ac:image[^>]*>[\s\S]*?<ri:attachment\s+ri:filename="([^"]+)"[^>]*\/?>[\s\S]*?<\/ac:image>/g;
    let match;
    while ((match = imageRegex.exec(htmlContent)) !== null) {
      referenced.add(match[1]);
    }
    
    // Extract from view-file macro
    const viewFileRegex = /<ac:structured-macro ac:name="view-file"[^>]*>[\s\S]*?<ri:attachment\s+ri:filename="([^"]+)"[^>]*\/?>[\s\S]*?<\/ac:structured-macro>/g;
    while ((match = viewFileRegex.exec(htmlContent)) !== null) {
      referenced.add(match[1]);
    }
    
    // Extract from any ri:attachment references
    const attachmentRegex = /<ri:attachment\s+ri:filename="([^"]+)"[^>]*\/?>/g;
    while ((match = attachmentRegex.exec(htmlContent)) !== null) {
      referenced.add(match[1]);
    }
    
    return referenced;
  }

  /**
   * Read a Confluence page content
   * @param {string} pageIdOrUrl - Page ID or URL
   * @param {string} format - Output format: 'text', 'html', 'storage', or 'markdown'
   * @param {object} options - Additional options
   * @param {boolean} options.resolveUsers - Whether to resolve userkeys to display names (default: true for markdown)
   * @param {boolean} options.extractReferencedAttachments - Whether to extract referenced attachments (default: false)
   */
  async readPage(pageIdOrUrl, format = 'text', options = {}) {
    const pageId = await this.extractPageId(pageIdOrUrl);

    if ((format || '').toLowerCase() === 'adf') {
      return this.readPageAdf(pageId);
    }

    let htmlContent = await this.readPageStorage(pageId);
    
    // Extract referenced attachments if requested
    if (options.extractReferencedAttachments) {
      this._referencedAttachments = this.extractReferencedAttachments(htmlContent);
    }
    
    if (format === 'html' || format === 'storage') {
      return htmlContent;
    }
    
    if (format === 'markdown') {
      // Resolve userkeys to display names before converting to markdown
      const resolveUsers = options.resolveUsers !== false;
      if (resolveUsers) {
        const { html: resolvedHtml } = await this.resolveUserKeysInHtml(htmlContent);
        htmlContent = resolvedHtml;
      }
      
      // Resolve page links to full URLs
      const resolvePageLinks = options.resolvePageLinks !== false;
      if (resolvePageLinks) {
        htmlContent = await this.resolvePageLinksInHtml(htmlContent);
      }
      
      // Resolve children macro to child pages list
      htmlContent = await this.resolveChildrenMacro(htmlContent, pageId);
      
      return this.storageToMarkdown(htmlContent);
    }
    
    // Convert HTML to text
    return convert(htmlContent, {
      wordwrap: 80,
      selectors: [
        { selector: 'h1', options: { uppercase: false } },
        { selector: 'h2', options: { uppercase: false } },
        { selector: 'h3', options: { uppercase: false } },
        { selector: 'table', options: { uppercaseHeaderCells: false } }
      ]
    });
  }

  shouldUseCloudV2PageApi() {
    return this.authType === 'oauth' && this.isCloud();
  }

  async readPageStorage(pageId) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.readPageStorageV2(pageId);
    }

    const response = await this.client.get(`/content/${pageId}`, {
      params: {
        expand: 'body.storage'
      }
    });

    return response.data.body.storage.value;
  }

  cloudV2BaseUrl() {
    const v2ApiPath = this.apiPath.endsWith('/rest/api')
      ? this.apiPath.replace(/\/rest\/api$/, '/api/v2')
      : `${this.webUrlPrefix || ''}/api/v2`;
    if (this.authType === 'oauth') {
      if (!this.oauth?.cloudId) {
        throw new Error('OAuth ADF operations require a Confluence Cloud ID. Run "confluence oauth-login" or set CONFLUENCE_CLOUD_ID.');
      }
      return `https://api.atlassian.com/ex/confluence/${this.oauth.cloudId}${v2ApiPath}`;
    }
    return `${this.protocol}://${this.domain}${v2ApiPath}`;
  }

  cloudV2Url(pathName) {
    const normalized = pathName.startsWith('/') ? pathName : `/${pathName}`;
    return `${this.cloudV2BaseUrl()}${normalized}`;
  }

  stringifyAdfForOutput(value) {
    if (value === undefined || value === null) {
      throw new Error('Confluence did not return an atlas_doc_format body for this page.');
    }
    if (typeof value === 'string') {
      try {
        return JSON.stringify(JSON.parse(value), null, 2);
      } catch {
        return value;
      }
    }
    return JSON.stringify(value, null, 2);
  }

  parseAdfInput(content) {
    if (content === undefined || content === null || content === '') {
      throw new Error('ADF content is required.');
    }
    let parsed;
    try {
      parsed = typeof content === 'string' ? JSON.parse(content) : content;
    } catch (error) {
      throw new Error(`Invalid ADF JSON: ${error.message}`);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('ADF content must be a JSON object.');
    }
    return JSON.stringify(parsed);
  }

  cloudV2PageBody(content, format = 'storage') {
    const normalizedFormat = (format || 'storage').toLowerCase();
    if (normalizedFormat === 'adf') {
      return {
        representation: 'atlas_doc_format',
        value: this.parseAdfInput(content)
      };
    }

    let storageContent = content;
    if (normalizedFormat === 'markdown') {
      storageContent = this.markdownToStorage(content);
    } else if (normalizedFormat === 'html') {
      storageContent = this.htmlToConfluenceStorage(content);
    }

    return {
      representation: 'storage',
      value: storageContent
    };
  }

  async resolveCloudV2SpaceId(spaceKeyOrId) {
    const value = String(spaceKeyOrId || '').trim();
    if (/^\d+$/.test(value)) {
      return value;
    }
    return this.resolveSpaceId(value);
  }

  async readPageAdf(pageId) {
    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
      params: { 'body-format': 'atlas_doc_format' }
    });
    return this.stringifyAdfForOutput(response.data?.body?.atlas_doc_format?.value);
  }

  async readPageStorageV2(pageId) {
    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
      params: { 'body-format': 'storage' }
    });
    const storageValue = response.data?.body?.storage?.value;
    if (storageValue === undefined || storageValue === null) {
      throw new Error('Confluence did not return a storage body for this page.');
    }
    return storageValue;
  }

  async resolveSpaceId(spaceKey) {
    const response = await this.client.get(this.cloudV2Url('/spaces'), {
      params: { keys: [spaceKey] },
      paramsSerializer: (params) => `keys=${encodeURIComponent(params.keys[0])}`
    });
    const space = response.data?.results?.[0];
    if (!space?.id) {
      throw new Error(`Could not resolve Confluence Cloud space ID for space key "${spaceKey}".`);
    }
    return String(space.id);
  }

  async getPageInfoV2(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}`));
    const page = response.data;
    return {
      id: String(page.id),
      title: page.title,
      type: page.type || 'page',
      status: page.status || 'current',
      spaceId: page.spaceId ? String(page.spaceId) : null,
      space: page.spaceId ? { id: String(page.spaceId), key: String(page.spaceId), name: String(page.spaceId) } : null,
      parentId: page.parentId ? String(page.parentId) : null,
      version: page.version?.number || null,
      url: page._links?.webui ? this.toAbsoluteUrl(page._links.webui, page._links?.base) : null
    };
  }

  normalizeV2ChildPage(page, fallbackParentId, depth = 1) {
    return {
      id: String(page.id),
      title: page.title,
      type: page.type || 'page',
      status: page.status || 'current',
      parentId: page.parentId ? String(page.parentId) : String(fallbackParentId),
      spaceId: page.spaceId ? String(page.spaceId) : undefined,
      version: page.version,
      url: page._links?.webui ? this.toAbsoluteUrl(page._links.webui, page._links?.base) : undefined,
      depth
    };
  }

  normalizeV2PageResult(page) {
    if (!page || typeof page !== 'object') {
      return page;
    }
    return {
      ...page,
      type: page.type || 'page',
      space: page.space || (page.spaceId ? { id: page.spaceId, key: page.spaceKey || String(page.spaceId), name: page.spaceName || String(page.spaceId) } : undefined),
      _links: page._links || { webui: page.links?.webui || page.webui || '' }
    };
  }

  /**
   * Get page information
   */
  async getPageInfo(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);

    if (this.shouldUseCloudV2PageApi()) {
      return this.getPageInfoV2(pageId);
    }
    
    const response = await this.client.get(`/content/${pageId}`, {
      params: {
        expand: 'space,history,version,ancestors'
      }
    });

    return this.normalizePage(response.data);
  }

  /**
   * Escape a string for safe use inside a CQL double-quoted literal.
   * Only escapes characters that can break out of the literal: backslash and
   * double quote. Wildcards (*, ?) and fuzzy (~) are left as-is so existing
   * search semantics are preserved.
   */
  escapeCql(str) {
    if (typeof str !== 'string') {
      return '';
    }
    return str
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"');
  }

  /**
   * Search for pages
   */
  async search(query, limit = 10, rawCql = false) {
    const cql = rawCql ? query : `text ~ "${this.escapeCql(query)}"`;
    const response = await this.client.get('/search', {
      params: {
        cql,
        limit: limit
      }
    });

    return response.data.results.map(result => {
      // Handle different result structures
      const content = result.content || result;
      return {
        id: content.id || 'Unknown',
        title: content.title || 'Untitled',
        type: content.type || 'Unknown',
        excerpt: result.excerpt || content.excerpt || ''
      };
    }).filter(item => item.id !== 'Unknown'); // Filter out items without valid IDs
  }

  /**
   * List a single page of spaces with pagination metadata
   */
  async listSpaces(options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.listSpacesV2(options);
    }

    const limit = this.parsePositiveInt(options.limit, 500);
    const start = this.parsePositiveInt(options.start, 0);

    const response = await this.client.get('/space', {
      params: { limit, start }
    });

    const results = Array.isArray(response.data?.results)
      ? response.data.results.map(space => ({
        key: space.key,
        name: space.name,
        type: space.type
      }))
      : [];

    return {
      results,
      nextStart: this.parseNextStart(response.data?._links?.next)
    };
  }

  /**
   * List Cloud spaces through REST v2. OAuth traffic is routed through
   * api.atlassian.com, where the legacy /rest/api/space endpoint may return 410.
   */
  async listSpacesV2(options = {}) {
    const requestedLimit = this.parsePositiveInt(options.limit, 250);
    const limit = Math.max(1, Math.min(requestedLimit, 250));
    const params = { limit };

    if (options.cursor) {
      params.cursor = options.cursor;
    }

    const response = await this.client.get(this.cloudV2Url('/spaces'), { params });
    const results = Array.isArray(response.data?.results)
      ? response.data.results.map(space => ({
        key: space.key,
        name: space.name,
        type: space.type
      }))
      : [];

    return {
      results,
      nextStart: this.parseNextCursor(response.data?._links?.next)
    };
  }

  /**
   * Get spaces, paginating through results until maxResults is reached or
   * the server stops returning a `_links.next`. Pass `null` to fetch every space.
   */
  async getSpaces(maxResults = 500, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getSpacesV2(maxResults, options);
    }

    const cap = maxResults === null || maxResults === undefined
      ? null
      : this.parsePositiveInt(maxResults, 500);
    const pageSize = this.parsePositiveInt(options.pageSize, 500);
    let start = this.parsePositiveInt(options.start, 0);
    const spaces = [];

    let hasNext = true;
    while (hasNext) {
      if (cap !== null && spaces.length >= cap) break;
      const requestLimit = cap === null
        ? pageSize
        : Math.min(pageSize, cap - spaces.length);
      const page = await this.listSpaces({ limit: requestLimit, start });
      spaces.push(...page.results);

      hasNext = page.nextStart !== null && page.nextStart !== undefined;
      if (hasNext) {
        start = page.nextStart;
      }
    }

    return cap !== null ? spaces.slice(0, cap) : spaces;
  }

  async getSpacesV2(maxResults = 500, options = {}) {
    const cap = maxResults === null || maxResults === undefined
      ? null
      : this.parsePositiveInt(maxResults, 500);
    const pageSize = Math.max(1, Math.min(this.parsePositiveInt(options.pageSize, 250), 250));
    let cursor = options.cursor || null;
    const spaces = [];

    let hasNext = true;
    while (hasNext) {
      if (cap !== null && spaces.length >= cap) break;
      const requestLimit = cap === null
        ? pageSize
        : Math.min(pageSize, cap - spaces.length);
      const page = await this.listSpacesV2({ limit: requestLimit, cursor });
      spaces.push(...page.results);

      hasNext = Boolean(page.nextStart);
      if (hasNext) {
        cursor = page.nextStart;
      }
    }

    return cap !== null ? spaces.slice(0, cap) : spaces;
  }

  /**
   * Get user information by userkey
   * @param {string} userKey - The user key (e.g., "8ad05c43962471ed0196c26107d7000c")
   * @returns {Promise<{key: string, displayName: string, username: string}>}
   */
  async getUserByKey(userKey) {
    try {
      const response = await this.client.get('/user', {
        params: { key: userKey }
      });
      return {
        key: userKey,
        displayName: response.data.displayName || response.data.username || userKey,
        username: response.data.username || ''
      };
    } catch (error) {
      // Return full userkey as fallback if user not found
      return {
        key: userKey,
        displayName: userKey,
        username: ''
      };
    }
  }

  /**
   * Resolve all userkeys in HTML to display names
   * @param {string} html - HTML content with ri:user elements
   * @returns {Promise<{html: string, userMap: Map<string, string>}>}
   */
  async resolveUserKeysInHtml(html) {
    // Extract all unique userkeys
    const userKeyRegex = /ri:userkey="([^"]+)"/g;
    const userKeys = new Set();
    let match;
    while ((match = userKeyRegex.exec(html)) !== null) {
      userKeys.add(match[1]);
    }

    if (userKeys.size === 0) {
      return { html, userMap: new Map() };
    }

    // Fetch user info for all keys in parallel; isolate per-key failures so a
    // single rejection doesn't drop display names for the rest of the page.
    const keysArray = Array.from(userKeys);
    const results = await Promise.allSettled(
      keysArray.map(key => this.getUserByKey(key))
    );

    // Build userkey -> displayName map. On rejection, fall back to the raw
    // userkey (mirrors getUserByKey's own caught-error fallback).
    const userMap = new Map();
    results.forEach((result, i) => {
      const key = keysArray[i];
      if (result.status === 'fulfilled') {
        userMap.set(result.value.key, result.value.displayName);
      } else {
        userMap.set(key, key);
      }
    });

    // Replace userkey references with display names in HTML
    let resolvedHtml = html;
    userMap.forEach((displayName, userKey) => {
      const escapedKey = userKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const userLinkRegex = new RegExp(
        `<ac:link>\\s*<ri:user\\s+ri:userkey="${escapedKey}"\\s*/>\\s*</ac:link>`,
        'g'
      );
      resolvedHtml = resolvedHtml.replace(userLinkRegex, () => `@${displayName}`);
    });

    return { html: resolvedHtml, userMap };
  }

  /**
   * Find a page by title and space key, return page info with URL
   * @param {string} spaceKey - Space key (e.g., "~huotui" or "TECH")
   * @param {string} title - Page title
   * @returns {Promise<{title: string, url: string} | null>}
   */
  async findPageByTitleAndSpace(spaceKey, title) {
    try {
      if (this.shouldUseCloudV2PageApi()) {
        const pageInfo = await this.findPageByTitle(title, spaceKey);
        return {
          title: pageInfo.title,
          url: this.toAbsoluteUrl(pageInfo.url)
        };
      }

      const response = await this.client.get('/content', {
        params: {
          spaceKey: spaceKey,
          title: title,
          limit: 1
        }
      });
      
      if (response.data.results && response.data.results.length > 0) {
        const page = response.data.results[0];
        const webui = page._links?.webui || '';
        return {
          title: page.title,
          url: webui ? this.toAbsoluteUrl(webui, page._links?.base) : ''
        };
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Resolve all page links in HTML to full URLs
   * @param {string} html - HTML content with ri:page elements
   * @returns {Promise<string>} - HTML with resolved page links
   */
  async resolvePageLinksInHtml(html) {
    // Extract all page links: <ri:page ri:space-key="xxx" ri:content-title="yyy" />
    const pageLinkRegex = /<ac:link>\s*<ri:page\s+ri:space-key="([^"]+)"\s+ri:content-title="([^"]+)"[^>]*(?:\/>|><\/ri:page>)\s*<\/ac:link>/g;
    const pageLinks = [];
    let match;
    
    while ((match = pageLinkRegex.exec(html)) !== null) {
      pageLinks.push({
        fullMatch: match[0],
        spaceKey: match[1],
        title: match[2]
      });
    }

    if (pageLinks.length === 0) {
      return html;
    }

    // Fetch page info for all links in parallel
    const pagePromises = pageLinks.map(async (link) => {
      const pageInfo = await this.findPageByTitleAndSpace(link.spaceKey, link.title);
      return {
        ...link,
        pageInfo
      };
    });
    
    const resolvedLinks = await Promise.all(pagePromises);

    // Replace page link references with markdown links
    let resolvedHtml = html;
    resolvedLinks.forEach(({ fullMatch, title, pageInfo }) => {
      let replacement;
      if (pageInfo && pageInfo.url) {
        replacement = `[${title}](${pageInfo.url})`;
      } else {
        // Fallback to just the title if page not found
        replacement = `[${title}]`;
      }
      resolvedHtml = resolvedHtml.replace(fullMatch, replacement);
    });

    return resolvedHtml;
  }

  /**
   * Resolve children macro to child pages list
   * @param {string} html - HTML content with children macro
   * @param {string} pageId - Page ID to get children from
   * @returns {Promise<string>} - HTML with children macro replaced by markdown list
   */
  async resolveChildrenMacro(html, pageId) {
    // Check if there's a children macro (self-closing or with closing tag)
    const childrenMacroRegex = /<ac:structured-macro\s+ac:name="children"[^>]*(?:\/>|>[\s\S]*?<\/ac:structured-macro>)/g;
    const hasChildrenMacro = childrenMacroRegex.test(html);
    
    if (!hasChildrenMacro) {
      return html;
    }

    try {
      const childPages = await this.getChildPages(pageId);
      
      if (childPages.length === 0) {
        // No children, remove the macro
        return html.replace(childrenMacroRegex, '');
      }

      // Convert child pages to markdown list
      // Format: - [Page Title](URL)
      const childPagesList = childPages.map(page => {
        const url = page.url || '';
        if (url) {
          return `- [${page.title}](${url})`;
        } else {
          return `- ${page.title}`;
        }
      }).join('\n');

      // Replace children macro with markdown list
      return html.replace(childrenMacroRegex, `\n${childPagesList}\n`);
    } catch (error) {
      // If error getting children, just remove the macro
      console.error(`Error resolving children macro: ${error.message}`);
      return html.replace(childrenMacroRegex, '');
    }
  }

  /**
   * List comments for a page with pagination support
   */
  async listComments(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.listCommentsV2(pageIdOrUrl, options);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 25);
    const start = this.parsePositiveInt(options.start, 0);
    const params = {
      limit,
      start
    };

    const expand = options.expand || 'body.storage,history,version,extensions.inlineProperties,extensions.resolution,ancestors';
    if (expand) {
      params.expand = expand;
    }

    if (options.parentVersion !== undefined && options.parentVersion !== null) {
      params.parentVersion = options.parentVersion;
    }

    if (options.location) {
      params.location = options.location;
    }

    if (options.depth) {
      params.depth = options.depth;
    }

    const paramsSerializer = (input) => {
      const searchParams = new URLSearchParams();
      Object.entries(input || {}).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') {
          return;
        }
        if (Array.isArray(value)) {
          value.forEach((item) => {
            if (item !== undefined && item !== null && item !== '') {
              searchParams.append(key, item);
            }
          });
          return;
        }
        searchParams.append(key, value);
      });
      return searchParams.toString();
    };

    const response = await this.client.get(`/content/${pageId}/child/comment`, {
      params,
      paramsSerializer
    });
    const results = Array.isArray(response.data?.results)
      ? response.data.results.map((item) => this.normalizeComment(item))
      : [];

    return {
      results,
      nextStart: this.parseNextStart(response.data?._links?.next)
    };
  }

  async listCommentsV2(pageIdOrUrl, options = {}) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 25);
    const locationValues = Array.isArray(options.location)
      ? options.location
      : (options.location ? [options.location] : []);
    const wantsInline = locationValues.length === 0 || locationValues.includes('inline') || locationValues.includes('resolved');
    const wantsFooter = locationValues.length === 0 || locationValues.includes('footer');
    const endpoints = [];

    if (wantsFooter) {
      endpoints.push({ path: `/pages/${pageId}/footer-comments`, location: 'footer' });
    }
    if (wantsInline) {
      endpoints.push({ path: `/pages/${pageId}/inline-comments`, location: 'inline' });
    }

    const results = [];
    let nextStart = null;
    for (const endpoint of endpoints) {
      const params = {
        limit,
        'body-format': 'storage'
      };
      if (options.cursor) {
        params.cursor = options.cursor;
      }
      if (endpoint.location === 'inline' && locationValues.includes('resolved')) {
        params['resolution-status'] = ['resolved'];
      }

      const response = await this.client.get(this.cloudV2Url(endpoint.path), { params });
      const pageResults = Array.isArray(response.data?.results)
        ? response.data.results.map((item) => this.normalizeV2Comment(item, endpoint.location))
        : [];
      results.push(...pageResults);
      nextStart = nextStart || this.parseNextCursor(response.data?._links?.next);
    }

    return {
      results: results.slice(0, limit),
      nextStart
    };
  }

  /**
   * Fetch all comments for a page, honoring an optional maxResults cap
   */
  async getAllComments(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getAllCommentsV2(pageIdOrUrl, options);
    }

    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 25);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    let start = this.parsePositiveInt(options.start, 0);
    const comments = [];

    let hasNext = true;
    while (hasNext) {
      const page = await this.listComments(pageIdOrUrl, {
        limit: pageSize,
        start,
        expand: options.expand,
        location: options.location,
        depth: options.depth,
        parentVersion: options.parentVersion
      });
      comments.push(...page.results);

      if (maxResults && comments.length >= maxResults) {
        return comments.slice(0, maxResults);
      }

      hasNext = page.nextStart !== null && page.nextStart !== undefined;
      if (hasNext) {
        start = page.nextStart;
      }
    }

    return comments;
  }

  async getAllCommentsV2(pageIdOrUrl, options = {}) {
    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 25);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    const locationValues = Array.isArray(options.location)
      ? options.location
      : (options.location ? [options.location] : []);
    const wantsInline = locationValues.length === 0 || locationValues.includes('inline') || locationValues.includes('resolved');
    const wantsFooter = locationValues.length === 0 || locationValues.includes('footer');
    const comments = [];

    const collect = async (location) => {
      let cursor = null;
      while (true) {
        const page = await this.listCommentsV2(pageIdOrUrl, {
          limit: pageSize,
          location,
          cursor
        });
        comments.push(...page.results);
        if (maxResults && comments.length >= maxResults) {
          return;
        }
        if (!page.nextStart) {
          return;
        }
        cursor = page.nextStart;
      }
    };

    if (wantsFooter) {
      await collect('footer');
    }
    if (!maxResults || comments.length < maxResults) {
      if (wantsInline) {
        await collect(locationValues.includes('resolved') ? 'resolved' : 'inline');
      }
    }

    return maxResults ? comments.slice(0, maxResults) : comments;
  }

  normalizeComment(raw) {
    const history = raw?.history || {};
    const author = history.createdBy || {};
    const extensions = raw?.extensions || {};
    const ancestors = Array.isArray(raw?.ancestors)
      ? raw.ancestors.map((ancestor) => {
        const id = ancestor?.id ?? ancestor;
        return {
          id: id !== undefined && id !== null ? String(id) : null,
          type: ancestor?.type || null,
          title: ancestor?.title || null
        };
      }).filter((ancestor) => ancestor.id)
      : [];

    return {
      id: raw?.id,
      title: raw?.title,
      status: raw?.status,
      body: raw?.body?.storage?.value || '',
      author: {
        displayName: author.displayName || author.publicName || author.username || author.userKey || author.accountId || 'Unknown',
        accountId: author.accountId,
        userKey: author.userKey,
        username: author.username,
        email: author.email
      },
      createdAt: history.createdDate || null,
      version: raw?.version?.number || null,
      location: this.getCommentLocation(extensions),
      inlineProperties: extensions.inlineProperties || null,
      resolution: this.getCommentResolution(extensions),
      parentId: this.getCommentParentId(ancestors),
      ancestors,
      extensions
    };
  }

  normalizeV2Comment(raw, location) {
    const version = raw?.version || {};
    return {
      id: raw?.id,
      title: raw?.title,
      status: raw?.status,
      body: raw?.body?.storage?.value || '',
      author: {
        displayName: version.authorId || raw?.authorId || 'Unknown',
        accountId: version.authorId || raw?.authorId
      },
      createdAt: version.createdAt || raw?.createdAt || null,
      version: version.number || null,
      location,
      inlineProperties: raw?.properties || null,
      resolution: raw?.resolutionStatus || null,
      parentId: raw?.parentCommentId ? String(raw.parentCommentId) : null,
      ancestors: [],
      extensions: raw
    };
  }

  getCommentParentId(ancestors = []) {
    if (!Array.isArray(ancestors) || ancestors.length === 0) {
      return null;
    }
    const commentAncestors = ancestors.filter((ancestor) => {
      const type = ancestor?.type ? String(ancestor.type).toLowerCase() : '';
      return type === 'comment';
    });
    if (commentAncestors.length === 0) {
      return null;
    }
    return commentAncestors[commentAncestors.length - 1].id || null;
  }

  getCommentLocation(extensions = {}) {
    const location = extensions.location;
    if (!location) {
      return null;
    }
    if (typeof location === 'string') {
      return location;
    }
    if (typeof location.value === 'string') {
      return location.value;
    }
    if (typeof location.name === 'string') {
      return location.name;
    }
    return null;
  }

  getCommentResolution(extensions = {}) {
    const resolution = extensions.resolution;
    if (!resolution) {
      return null;
    }
    if (typeof resolution === 'string') {
      return resolution;
    }
    if (typeof resolution.status === 'string') {
      return resolution.status;
    }
    if (typeof resolution.value === 'string') {
      return resolution.value;
    }
    return null;
  }

  formatCommentBody(storageValue, format = 'text') {
    const value = storageValue || '';
    if (format === 'storage' || format === 'html') {
      return value;
    }
    if (format === 'markdown') {
      return this.storageToMarkdown(value);
    }

    return convert(value, {
      wordwrap: 80,
      selectors: [
        { selector: 'h1', options: { uppercase: false } },
        { selector: 'h2', options: { uppercase: false } },
        { selector: 'h3', options: { uppercase: false } },
        { selector: 'table', options: { uppercaseHeaderCells: false } }
      ]
    });
  }

  /**
   * Create a comment on a page
   */
  async createComment(pageIdOrUrl, content, format = 'storage', options = {}) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    let storageContent = content;

    if (format === 'markdown') {
      storageContent = this.markdownToStorage(content);
    } else if (format === 'html') {
      storageContent = this.htmlToConfluenceStorage(content);
    }

    const commentData = {
      type: 'comment',
      container: {
        id: pageId,
        type: 'page'
      },
      body: {
        storage: {
          value: storageContent,
          representation: 'storage'
        }
      }
    };

    if (options.parentId) {
      commentData.ancestors = [{ id: options.parentId }];
    }

    const extensions = {};
    const location = options.location || (options.inlineProperties ? 'inline' : null);
    if (location) {
      extensions.location = location;
    }
    if (options.inlineProperties) {
      extensions.inlineProperties = options.inlineProperties;
    }
    if (Object.keys(extensions).length > 0) {
      commentData.extensions = extensions;
    }

    if (this.shouldUseCloudV2PageApi()) {
      const location = options.location || (options.inlineProperties ? 'inline' : 'footer');
      const payload = {
        pageId: String(pageId),
        body: {
          representation: 'storage',
          value: storageContent
        }
      };
      if (options.parentId) {
        payload.parentCommentId = String(options.parentId);
      }
      if (location === 'inline') {
        payload.inlineCommentProperties = options.inlineProperties || {};
      }

      const endpoint = location === 'inline' ? '/inline-comments' : '/footer-comments';
      const response = await this.client.post(this.cloudV2Url(endpoint), payload);
      return response.data;
    }

    const response = await this.client.post('/content', commentData);
    return response.data;
  }

  /**
   * Delete a comment by ID
   */
  async deleteComment(commentId) {
    if (this.shouldUseCloudV2PageApi()) {
      try {
        await this.client.delete(this.cloudV2Url(`/footer-comments/${commentId}`));
      } catch (error) {
        const status = error.response && error.response.status;
        if (status !== 404) {
          throw error;
        }
        await this.client.delete(this.cloudV2Url(`/inline-comments/${commentId}`));
      }
      return { id: String(commentId) };
    }

    await this.client.delete(`/content/${commentId}`);
    return { id: String(commentId) };
  }

  /**
   * List attachments for a page with pagination support
   */
  async listAttachments(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.listAttachmentsV2(pageIdOrUrl, options);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 50);
    const start = this.parsePositiveInt(options.start, 0);
    const params = {
      limit,
      start
    };

    if (options.filename) {
      params.filename = options.filename;
    }

    const response = await this.client.get(`/content/${pageId}/child/attachment`, { params });
    const results = Array.isArray(response.data.results)
      ? response.data.results.map((item) => this.normalizeAttachment(item))
      : [];

    return {
      results,
      nextStart: this.parseNextStart(response.data?._links?.next)
    };
  }

  async listAttachmentsV2(pageIdOrUrl, options = {}) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 50);
    const params = { limit };

    if (options.cursor) {
      params.cursor = options.cursor;
    }
    if (options.filename) {
      params.filename = options.filename;
    }

    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}/attachments`), { params });
    const results = Array.isArray(response.data?.results)
      ? response.data.results.map((item) => this.normalizeAttachment(item))
      : [];

    return {
      results,
      nextStart: this.parseNextCursor(response.data?._links?.next)
    };
  }

  /**
   * Fetch all attachments for a page, honoring an optional maxResults cap
   */
  async getAllAttachments(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getAllAttachmentsV2(pageIdOrUrl, options);
    }

    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 50);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    const filename = options.filename;
    let start = this.parsePositiveInt(options.start, 0);
    const attachments = [];

    let hasNext = true;
    while (hasNext) {
      const page = await this.listAttachments(pageIdOrUrl, {
        limit: pageSize,
        start,
        filename
      });
      attachments.push(...page.results);

      if (maxResults && attachments.length >= maxResults) {
        return attachments.slice(0, maxResults);
      }

      hasNext = page.nextStart !== null && page.nextStart !== undefined;
      if (hasNext) {
        start = page.nextStart;
      }
    }

    return attachments;
  }

  async getAllAttachmentsV2(pageIdOrUrl, options = {}) {
    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 50);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    const filename = options.filename;
    let cursor = options.cursor || null;
    const attachments = [];

    while (true) {
      const page = await this.listAttachmentsV2(pageIdOrUrl, {
        limit: pageSize,
        cursor,
        filename
      });
      attachments.push(...page.results);

      if (maxResults && attachments.length >= maxResults) {
        return attachments.slice(0, maxResults);
      }
      if (!page.nextStart) {
        return attachments;
      }
      cursor = page.nextStart;
    }
  }

  /**
   * Download an attachment's data stream
   * Now uses the download link from attachment metadata instead of the broken REST API endpoint
   */
  async downloadAttachment(pageIdOrUrl, attachmentIdOrAttachment, options = {}) {
    let downloadUrl;

    // If the second argument is an attachment object with downloadLink, use it directly
    if (typeof attachmentIdOrAttachment === 'object' && attachmentIdOrAttachment.downloadLink) {
      downloadUrl = attachmentIdOrAttachment.downloadLink;
    } else {
      // Otherwise, fetch attachment info to get the download link
      const pageId = await this.extractPageId(pageIdOrUrl);
      const attachmentId = attachmentIdOrAttachment;
      const response = await this.client.get(`/content/${pageId}/child/attachment`, {
        params: { limit: 500 }
      });
      const attachment = response.data.results.find(att => att.id === String(attachmentId));
      if (!attachment) {
        throw new Error(`Attachment with ID ${attachmentId} not found on page ${pageId}`);
      }
      downloadUrl = this.toAbsoluteUrl(attachment._links?.download);
    }

    if (!downloadUrl) {
      throw new Error('Unable to determine download URL for attachment');
    }

    // Refuse to send credentials to an unexpected origin. The download URL is
    // derived from a server-supplied _links.download value, so a tampered or
    // misconfigured response could otherwise exfiltrate the bearer/basic token,
    // including via an http:// downgrade against an https-configured client.
    this.assertSameOrigin(downloadUrl);

    // Download directly using axios with the same auth headers
    const downloadHeaders = this.authType === 'oauth'
      ? { Authorization: `Bearer ${await this.getOAuthAccessToken()}` }
      : this.buildAuthHeaders();
    const downloadRequestConfig = {
      responseType: options.responseType || 'stream',
      headers: downloadHeaders
    };
    const httpsAgent = this.buildHttpsAgent();
    if (httpsAgent) {
      downloadRequestConfig.httpsAgent = httpsAgent;
    }
    const downloadResponse = await axios.get(downloadUrl, downloadRequestConfig);
    return downloadResponse.data;
  }

  /**
   * Upload an attachment to a page
   */
  async uploadAttachment(pageIdOrUrl, filePath, options = {}) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('File path is required for attachment upload.');
    }

    const resolvedPath = path.resolve(filePath);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const form = new FormData();
    form.append('file', fs.createReadStream(resolvedPath), { filename: path.basename(resolvedPath) });

    if (options.comment !== undefined && options.comment !== null) {
      form.append('comment', options.comment, { contentType: 'text/plain; charset=utf-8' });
    }

    if (typeof options.minorEdit === 'boolean') {
      form.append('minorEdit', options.minorEdit ? 'true' : 'false');
    }

    const method = options.replace ? 'put' : 'post';
    const response = await this.client.request({
      url: `/content/${pageId}/child/attachment`,
      method,
      headers: {
        ...form.getHeaders(),
        'X-Atlassian-Token': 'nocheck'
      },
      data: form,
      maxBodyLength: Infinity,
      maxContentLength: Infinity
    });

    const results = Array.isArray(response.data?.results)
      ? response.data.results.map((item) => this.normalizeAttachment(item))
      : [];

    return {
      results,
      raw: response.data
    };
  }

  /**
   * Delete an attachment by ID
   */
  async deleteAttachment(pageIdOrUrl, attachmentId) {
    if (!attachmentId) {
      throw new Error('Attachment ID is required.');
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    if (this.shouldUseCloudV2PageApi()) {
      await this.client.delete(this.cloudV2Url(`/attachments/${attachmentId}`));
      return { id: String(attachmentId), pageId: String(pageId) };
    }

    await this.client.delete(`/content/${pageId}/child/attachment/${attachmentId}`);
    return { id: String(attachmentId), pageId: String(pageId) };
  }

  /**
   * List content properties for a page with pagination support
   */
  async listProperties(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.listPropertiesV2(pageIdOrUrl, options);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 25);
    const start = this.parsePositiveInt(options.start, 0);
    const params = { limit, start };

    const response = await this.client.get(`/content/${pageId}/property`, { params });
    const results = Array.isArray(response.data.results) ? response.data.results : [];

    return {
      results,
      nextStart: this.parseNextStart(response.data?._links?.next)
    };
  }

  async listPropertiesV2(pageIdOrUrl, options = {}) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = this.parsePositiveInt(options.limit, 25);
    const params = { limit };

    if (options.cursor) {
      params.cursor = options.cursor;
    }
    if (options.key) {
      params.key = options.key;
    }

    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}/properties`), { params });
    const results = Array.isArray(response.data?.results) ? response.data.results : [];

    return {
      results,
      nextStart: this.parseNextCursor(response.data?._links?.next)
    };
  }

  /**
   * Fetch all content properties for a page, honoring an optional maxResults cap
   */
  async getAllProperties(pageIdOrUrl, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getAllPropertiesV2(pageIdOrUrl, options);
    }

    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 25);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    let start = this.parsePositiveInt(options.start, 0);
    const properties = [];

    let hasNext = true;
    while (hasNext) {
      const page = await this.listProperties(pageIdOrUrl, {
        limit: pageSize,
        start
      });
      properties.push(...page.results);

      if (maxResults && properties.length >= maxResults) {
        return properties.slice(0, maxResults);
      }

      hasNext = page.nextStart !== null && page.nextStart !== undefined;
      if (hasNext) {
        start = page.nextStart;
      }
    }

    return properties;
  }

  async getAllPropertiesV2(pageIdOrUrl, options = {}) {
    const pageSize = this.parsePositiveInt(options.pageSize || options.limit, 25);
    const maxResults = this.parsePositiveInt(options.maxResults, null);
    let cursor = options.cursor || null;
    const properties = [];

    while (true) {
      const page = await this.listPropertiesV2(pageIdOrUrl, {
        limit: pageSize,
        cursor,
        key: options.key
      });
      properties.push(...page.results);

      if (maxResults && properties.length >= maxResults) {
        return properties.slice(0, maxResults);
      }
      if (!page.nextStart) {
        return properties;
      }
      cursor = page.nextStart;
    }
  }

  /**
   * Get a single content property by key
   */
  async getProperty(pageIdOrUrl, key) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getPropertyV2(pageIdOrUrl, key);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const response = await this.client.get(`/content/${pageId}/property/${encodeURIComponent(key)}`);
    return response.data;
  }

  async findPropertyByKeyV2(pageIdOrUrl, key) {
    const properties = await this.getAllPropertiesV2(pageIdOrUrl, { key });
    return properties.find((property) => property.key === key) || null;
  }

  async getPropertyV2(pageIdOrUrl, key) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const property = await this.findPropertyByKeyV2(pageId, key);
    if (!property?.id) {
      const error = new Error(`Property not found: "${key}"`);
      error.response = { status: 404 };
      throw error;
    }

    const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}/properties/${property.id}`));
    return response.data;
  }

  /**
   * Set (create or update) a content property
   */
  async setProperty(pageIdOrUrl, key, value) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.setPropertyV2(pageIdOrUrl, key, value);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    const encodedKey = encodeURIComponent(key);

    let version = 1;
    try {
      const existing = await this.client.get(`/content/${pageId}/property/${encodedKey}`);
      version = existing.data.version.number + 1;
    } catch (err) {
      if (!err.response || err.response.status !== 404) {
        throw err;
      }
    }

    const response = await this.client.put(`/content/${pageId}/property/${encodedKey}`, {
      key,
      value,
      version: { number: version }
    });
    return response.data;
  }

  async setPropertyV2(pageIdOrUrl, key, value) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const existing = await this.findPropertyByKeyV2(pageId, key);
    if (!existing?.id) {
      const response = await this.client.post(this.cloudV2Url(`/pages/${pageId}/properties`), {
        key,
        value
      });
      return response.data;
    }

    const version = (existing.version?.number || 1) + 1;
    const response = await this.client.put(this.cloudV2Url(`/pages/${pageId}/properties/${existing.id}`), {
      key,
      value,
      version: { number: version }
    });
    return response.data;
  }

  /**
   * Delete a content property by key
   */
  async deleteProperty(pageIdOrUrl, key) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.deletePropertyV2(pageIdOrUrl, key);
    }

    const pageId = await this.extractPageId(pageIdOrUrl);
    await this.client.delete(`/content/${pageId}/property/${encodeURIComponent(key)}`);
    return { pageId: String(pageId), key };
  }

  async deletePropertyV2(pageIdOrUrl, key) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const property = await this.findPropertyByKeyV2(pageId, key);
    if (!property?.id) {
      const error = new Error(`Property not found: "${key}"`);
      error.response = { status: 404 };
      throw error;
    }

    await this.client.delete(this.cloudV2Url(`/pages/${pageId}/properties/${property.id}`));
    return { pageId: String(pageId), key };
  }

  markdownToStorage(markdown) {
    return this.converter.markdownToStorage(markdown);
  }

  htmlToConfluenceStorage(html) {
    return this.converter.htmlToConfluenceStorage(html);
  }

  markdownToNativeStorage(markdown) {
    return this.converter.markdownToNativeStorage(markdown);
  }

  setupConfluenceMarkdownExtensions() {
    this.converter.setupConfluenceMarkdownExtensions();
  }

  detectLanguageLabels(text) {
    return this.converter.detectLanguageLabels(text);
  }

  storageToMarkdown(storage, options = {}) {
    return this.converter.storageToMarkdown(storage, options);
  }

  htmlToMarkdown(html) {
    return htmlToMarkdown(html);
  }

  /**
   * Create a new Confluence page
   */
  async createPage(title, spaceKey, content, format = 'storage', type = 'page') {
    if (this.shouldUseCloudV2PageApi()) {
      const spaceId = await this.resolveCloudV2SpaceId(spaceKey);
      if (type === 'folder') {
        const response = await this.client.post(this.cloudV2Url('/folders'), {
          spaceId,
          title
        });
        return this.normalizeV2PageResult(response.data);
      }

      const response = await this.client.post(this.cloudV2Url('/pages'), {
        spaceId,
        status: 'current',
        title,
        body: this.cloudV2PageBody(content, format)
      });
      return this.normalizeV2PageResult(response.data);
    }

    if ((format || '').toLowerCase() === 'adf') {
      if (type !== 'page') {
        throw new Error('ADF format is only supported for page content.');
      }
      const adfValue = this.parseAdfInput(content);
      const spaceId = await this.resolveSpaceId(spaceKey);
      const response = await this.client.post(this.cloudV2Url('/pages'), {
        spaceId,
        status: 'current',
        title,
        body: {
          representation: 'atlas_doc_format',
          value: adfValue
        }
      });
      return this.normalizeV2PageResult(response.data);
    }

    const pageData = {
      type: type,
      title: title,
      space: {
        key: spaceKey
      }
    };

    if (type !== 'folder') {
      let storageContent = content;

      if (format === 'markdown') {
        storageContent = this.markdownToStorage(content);
      } else if (format === 'html') {
        // Convert HTML directly to storage format (no macro wrapper)
        storageContent = content;
      }

      pageData.body = {
        storage: {
          value: storageContent,
          representation: 'storage'
        }
      };
    }

    const response = await this.client.post('/content', pageData);
    return response.data;
  }

  /**
   * Create a new Confluence page as a child of another page
   */
  async createChildPage(title, spaceKey, parentId, content, format = 'storage', type = 'page') {
    if (this.shouldUseCloudV2PageApi()) {
      const spaceId = await this.resolveCloudV2SpaceId(spaceKey);
      if (type === 'folder') {
        const response = await this.client.post(this.cloudV2Url('/folders'), {
          spaceId,
          title,
          parentId: String(parentId)
        });
        return this.normalizeV2PageResult(response.data);
      }

      const response = await this.client.post(this.cloudV2Url('/pages'), {
        spaceId,
        status: 'current',
        title,
        parentId: String(parentId),
        body: this.cloudV2PageBody(content, format)
      });
      return this.normalizeV2PageResult(response.data);
    }

    if ((format || '').toLowerCase() === 'adf') {
      if (type !== 'page') {
        throw new Error('ADF format is only supported for page content.');
      }
      const adfValue = this.parseAdfInput(content);
      const spaceId = await this.resolveSpaceId(spaceKey);
      const response = await this.client.post(this.cloudV2Url('/pages'), {
        spaceId,
        status: 'current',
        title,
        parentId: String(parentId),
        body: {
          representation: 'atlas_doc_format',
          value: adfValue
        }
      });
      return this.normalizeV2PageResult(response.data);
    }

    const pageData = {
      type: type,
      title: title,
      space: {
        key: spaceKey
      },
      ancestors: [
        {
          id: parentId
        }
      ]
    };

    if (type !== 'folder') {
      let storageContent = content;

      if (format === 'markdown') {
        storageContent = this.markdownToStorage(content);
      } else if (format === 'html') {
        // Convert HTML directly to storage format (no macro wrapper)
        storageContent = content;
      }

      pageData.body = {
        storage: {
          value: storageContent,
          representation: 'storage'
        }
      };
    }

    const response = await this.client.post('/content', pageData);
    return response.data;
  }

  async createChildPageFromParent(title, parentIdOrUrl, content, format = 'storage', type = 'page') {
    const parentId = await this.extractPageId(parentIdOrUrl);
    if ((format || '').toLowerCase() !== 'adf') {
      const parentInfo = await this.getPageInfo(parentId);
      return this.createChildPage(title, parentInfo.spaceId || parentInfo.space.key, parentId, content, format, type);
    }
    if (type !== 'page') {
      throw new Error('ADF format is only supported for page content.');
    }
    const adfValue = this.parseAdfInput(content);
    const parentInfo = await this.getPageInfoV2(parentId);
    if (!parentInfo.spaceId) {
      throw new Error(`Could not determine parent page space ID for page ${parentId}.`);
    }
    const response = await this.client.post(this.cloudV2Url('/pages'), {
      spaceId: parentInfo.spaceId,
      status: 'current',
      title,
      parentId: String(parentId),
      body: {
        representation: 'atlas_doc_format',
        value: adfValue
      }
    });
    return this.normalizeV2PageResult(response.data);
  }

  /**
   * Update an existing Confluence page
   */
  async updatePage(pageIdOrUrl, title, content, format = 'storage') {
    const pageId = await this.extractPageId(pageIdOrUrl);
    if (this.shouldUseCloudV2PageApi()) {
      const normalizedFormat = (format || 'storage').toLowerCase();
      const bodyFormat = normalizedFormat === 'adf' ? 'atlas_doc_format' : 'storage';
      const currentPage = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
        params: { 'body-format': bodyFormat }
      });
      const current = currentPage.data;
      const currentVersion = current.version?.number;
      if (!currentVersion) {
        throw new Error('Could not determine current page version for update.');
      }

      let body;
      if (content !== undefined && content !== null) {
        body = this.cloudV2PageBody(content, format);
      } else if (bodyFormat === 'atlas_doc_format') {
        body = {
          representation: 'atlas_doc_format',
          value: this.stringifyAdfForOutput(current.body?.atlas_doc_format?.value)
        };
      } else {
        body = {
          representation: 'storage',
          value: current.body?.storage?.value || ''
        };
      }

      const response = await this.client.put(this.cloudV2Url(`/pages/${pageId}`), {
        id: String(pageId),
        status: current.status || 'current',
        title: title || current.title,
        spaceId: current.spaceId,
        parentId: current.parentId,
        body,
        version: {
          number: currentVersion + 1
        }
      });
      return this.normalizeV2PageResult(response.data);
    }

    if ((format || '').toLowerCase() === 'adf') {
      const requestedAdfValue = content !== undefined && content !== null
        ? this.parseAdfInput(content)
        : null;
      const currentPage = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
        params: { 'body-format': 'atlas_doc_format' }
      });
      const current = currentPage.data;
      const currentVersion = current.version?.number;
      if (!currentVersion) {
        throw new Error('Could not determine current page version for ADF update.');
      }
      const currentAdf = current.body?.atlas_doc_format?.value;
      const adfValue = requestedAdfValue !== null
        ? requestedAdfValue
        : this.stringifyAdfForOutput(currentAdf);
      const response = await this.client.put(this.cloudV2Url(`/pages/${pageId}`), {
        id: String(pageId),
        status: current.status || 'current',
        title: title || current.title,
        body: {
          representation: 'atlas_doc_format',
          value: adfValue
        },
        version: {
          number: currentVersion + 1
        }
      });
      return this.normalizeV2PageResult(response.data);
    }

    // First, get the current page to get the version number and existing content
    const currentPage = await this.client.get(`/content/${pageId}`, {
      params: {
        expand: 'body.storage,version,space'
      }
    });
    const currentVersion = currentPage.data.version.number;

    let storageContent;

    if (content !== undefined && content !== null) {
      // If new content is provided, convert it to storage format
      if (format === 'markdown') {
        storageContent = this.markdownToStorage(content);
      } else if (format === 'html') {
        storageContent = this.htmlToConfluenceStorage(content); // Using the conversion function for robustness
      } else { // 'storage' format
        storageContent = content;
      }
    } else {
      // If no new content, use the existing content
      storageContent = currentPage.data.body.storage.value;
    }

    const pageData = {
      id: pageId,
      type: 'page',
      title: title || currentPage.data.title,
      space: currentPage.data.space,
      body: {
        storage: {
          value: storageContent,
          representation: 'storage'
        }
      },
      version: {
        number: currentVersion + 1
      }
    };

    const response = await this.client.put(`/content/${pageId}`, pageData);
    return response.data;
  }

  /**
   * Move a page to a new parent location
   */
  async movePage(pageIdOrUrl, newParentIdOrUrl, newTitle = null) {
    // Resolve both IDs from URLs if needed
    const pageId = await this.extractPageId(pageIdOrUrl);
    const newParentId = await this.extractPageId(newParentIdOrUrl);

    if (this.shouldUseCloudV2PageApi()) {
      const currentPage = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
        params: { 'body-format': 'storage' }
      });
      const parentPage = await this.client.get(this.cloudV2Url(`/pages/${newParentId}`));
      const current = currentPage.data;
      const parent = parentPage.data;

      if (current.spaceId && parent.spaceId && String(current.spaceId) !== String(parent.spaceId)) {
        throw new Error(
          `Cannot move page across spaces. Page is in space "${current.spaceId}" ` +
          `but new parent is in space "${parent.spaceId}". ` +
          'Pages can only be moved within the same space.'
        );
      }

      const response = await this.client.put(this.cloudV2Url(`/pages/${pageId}`), {
        id: String(pageId),
        status: current.status || 'current',
        title: newTitle || current.title,
        spaceId: current.spaceId,
        parentId: String(newParentId),
        body: {
          representation: 'storage',
          value: current.body?.storage?.value || ''
        },
        version: {
          number: (current.version?.number || 1) + 1
        }
      });
      return this.normalizeV2PageResult(response.data);
    }

    // Fetch current page
    const response = await this.client.get(`/content/${pageId}`, {
      params: { expand: 'body.storage,version,space' }
    });
    const { version, title, body, space } = response.data;

    // Fetch new parent to get its space (for validation)
    const parentResponse = await this.client.get(`/content/${newParentId}`, {
      params: { expand: 'space' }
    });
    const parentSpace = parentResponse.data.space;

    // Validate same space
    if (parentSpace.key !== space.key) {
      throw new Error(
        `Cannot move page across spaces. Page is in space "${space.key}" ` +
        `but new parent is in space "${parentSpace.key}". ` +
        'Pages can only be moved within the same space.'
      );
    }

    // Proceed with move
    const pageData = {
      id: pageId,
      type: 'page',
      title: newTitle || title,
      space: { key: space.key },
      body: {
        storage: {
          value: body.storage.value,
          representation: 'storage'
        }
      },
      version: { number: version.number + 1 },
      ancestors: [{ id: newParentId }]
    };

    const updateResponse = await this.client.put(`/content/${pageId}`, pageData);
    return updateResponse.data;
  }

  /**
   * Get page content for editing
   */
  async getPageForEdit(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);

    if (this.shouldUseCloudV2PageApi()) {
      const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}`), {
        params: { 'body-format': 'storage' }
      });
      const page = response.data;
      const spaceId = page.spaceId ? String(page.spaceId) : null;
      return {
        id: String(page.id),
        title: page.title,
        content: page.body?.storage?.value || '',
        version: page.version?.number || null,
        space: { id: spaceId, key: spaceId, name: spaceId }
      };
    }
    
    const response = await this.client.get(`/content/${pageId}`, {
      params: {
        expand: 'body.storage,version,space'
      }
    });

    return {
      id: response.data.id,
      title: response.data.title,
      content: response.data.body.storage.value,
      version: response.data.version.number,
      space: response.data.space
    };
  }

  /**
   * Delete a Confluence page
   * Note: Confluence may move the page to trash depending on instance settings.
   */
  async deletePage(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    if (this.shouldUseCloudV2PageApi()) {
      await this.client.delete(this.cloudV2Url(`/pages/${pageId}`));
      return { id: String(pageId) };
    }

    await this.client.delete(`/content/${pageId}`);
    return { id: String(pageId) };
  }

  /**
   * Build the absolute URL for the experimental version endpoint.
   * Confluence Server/Data Center exposes content versions only at
   * /rest/experimental/ (the modern /rest/api/.../version path 404s
   * there). Cloud accepts both. We use this as a fallback when the
   * configured apiPath returns 404/405.
   */
  experimentalVersionUrl(pageId, versionNumber = null) {
    const base = `${this.protocol}://${this.domain}${this.webUrlPrefix}/rest/experimental/content/${pageId}/version`;
    return versionNumber == null ? base : `${base}/${versionNumber}`;
  }

  /**
   * List historical versions of a page. Returns an array sorted by
   * version number ascending. Each entry has: number, when, by,
   * minorEdit, message.
   *
   * Pages with many versions (e.g. heavily edited or repeatedly
   * uploaded) may exceed a single page of results, so this paginates
   * via start/limit until all versions are collected.
   *
   * Path strategy: try the configured /rest/api/ path first; on 404
   * or 405 (typical of Server/DC where the version endpoints live
   * under /rest/experimental/), fall back transparently. Subsequent
   * pages use whichever path succeeded so we don't double the
   * round-trip count on long histories.
   */
  async listVersions(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    if (this.shouldUseCloudV2PageApi()) {
      return this.listVersionsV2(pageId);
    }

    const limit = 200;
    let start = 0;
    let useExperimental = false;
    const all = [];
    while (true) {
      let response;
      try {
        const url = useExperimental
          ? this.experimentalVersionUrl(pageId)
          : `/content/${pageId}/version`;
        response = await this.client.get(url, { params: { start, limit } });
      } catch (error) {
        const status = error.response && error.response.status;
        if (!useExperimental && (status === 404 || status === 405)) {
          useExperimental = true;
          continue;
        }
        throw error;
      }
      const results = response.data.results || [];
      all.push(...results);
      if (results.length < limit) {
        break;
      }
      start += limit;
    }
    return all.map(v => ({
      number: v.number,
      when: v.when,
      by: v.by ? (v.by.displayName || v.by.publicName || v.by.email || null) : null,
      minorEdit: v.minorEdit === true,
      message: v.message || ''
    })).sort((a, b) => a.number - b.number);
  }

  async listVersionsV2(pageIdOrUrl) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const limit = 200;
    let cursor = null;
    const all = [];

    while (true) {
      const params = { limit };
      if (cursor) {
        params.cursor = cursor;
      }
      const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}/versions`), { params });
      all.push(...(response.data?.results || []));
      cursor = this.parseNextCursor(response.data?._links?.next);
      if (!cursor) {
        break;
      }
    }

    return all.map(v => ({
      number: v.number,
      when: v.createdAt,
      by: v.authorId || null,
      minorEdit: v.minorEdit === true,
      message: v.message || ''
    })).sort((a, b) => a.number - b.number);
  }

  /**
   * Delete a single historical version of a page.
   *
   * Confluence refuses to delete the current version (returns 400).
   * The "rolled up into the next version" wording in Atlassian's
   * docs refers to the diff representation; the deleted version's
   * snapshot is removed from page history.
   *
   * Server/DC instances expose this only at /rest/experimental/, so
   * a 404 or 405 on the configured /rest/api/ path triggers a
   * one-shot retry against the experimental URL.
   */
  async deleteVersion(pageIdOrUrl, versionNumber) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const n = Number(versionNumber);
    if (!Number.isInteger(n) || n < 1) {
      throw new Error(`versionNumber must be a positive integer, got: ${versionNumber}`);
    }
    try {
      await this.client.delete(`/content/${pageId}/version/${n}`);
      return { id: String(pageId), versionNumber: n, viaExperimental: false };
    } catch (error) {
      const status = error.response && error.response.status;
      if (status !== 404 && status !== 405) {
        throw error;
      }
      await this.client.delete(this.experimentalVersionUrl(pageId, n));
      return { id: String(pageId), versionNumber: n, viaExperimental: true };
    }
  }

  /**
   * Delete every non-current version of a page. Used to purge the
   * historical content snapshots that may still hold a leaked secret
   * even after the current version has been overwritten with a
   * redacted copy.
   *
   * Returns { id, kept, deleted, failed } where `kept` is the version
   * number that survived (the current one) and `deleted`/`failed` are
   * the counts of historical versions removed/errored.
   */
  async purgeNonCurrentVersions(pageIdOrUrl, options = {}) {
    const onProgress = typeof options.onProgress === 'function' ? options.onProgress : () => {};
    const pageId = String(await this.extractPageId(pageIdOrUrl));
    const versions = await this.listVersions(pageId);

    if (versions.length === 0) {
      return { id: pageId, kept: null, deleted: 0, failed: 0, errors: [] };
    }

    const max = Math.max(...versions.map(v => v.number));
    // Delete in descending order. Some Confluence builds renumber
    // historical versions when an earlier one is removed; deleting
    // newest-first sidesteps the resulting off-by-one drift.
    const toDelete = versions
      .filter(v => v.number !== max)
      .map(v => v.number)
      .sort((a, b) => b - a);

    let deleted = 0;
    const errors = [];
    for (const n of toDelete) {
      try {
        const res = await this.deleteVersion(pageId, n);
        deleted += 1;
        onProgress({ kind: 'deleted', versionNumber: n, viaExperimental: res.viaExperimental });
      } catch (error) {
        const detail = error.response
          ? `HTTP ${error.response.status} ${error.response.statusText || ''}`.trim()
          : error.message;
        errors.push({ versionNumber: n, message: detail });
        onProgress({ kind: 'failed', versionNumber: n, message: detail });
      }
    }

    return { id: pageId, kept: max, deleted, failed: errors.length, errors };
  }

  /**
   * Search for a page by title and space
   */
  async findPageByTitle(title, spaceKey = null) {
    let cql = `title = "${this.escapeCql(title)}"`;
    if (spaceKey) {
      cql += ` AND space = "${this.escapeCql(spaceKey)}"`;
    }

    const response = await this.client.get('/search', {
      params: {
        cql: cql,
        limit: 1,
        expand: 'content.space'
      }
    });

    if (response.data.results.length === 0) {
      throw new Error(`Page not found: "${title}"`);
    }

    const result = response.data.results[0];
    const content = result.content || result;
    
    return {
      id: content.id,
      title: content.title,
      space: content.space || { key: spaceKey || 'Unknown', name: 'Unknown' },
      url: content._links?.webui || ''
    };
  }

  /**
   * Get child pages of a given page
   */
  async getChildPages(pageId, limit = 500, options = {}) {
    if (this.shouldUseCloudV2PageApi()) {
      return this.getChildPagesV2(pageId, limit);
    }

    const includeAncestors = Boolean(options.includeAncestors);
    const response = await this.client.get(`/content/${pageId}/child/page`, {
      params: {
        limit: limit,
        // Fetch lightweight payload; content fetched on-demand when copying
        expand: includeAncestors ? 'space,version,ancestors' : 'space,version'
      }
    });

    return response.data.results.map(page => this.normalizePage(page, {
      parentId: pageId,
      depth: 1
    }));
  }

  async getChildPagesV2(pageIdOrUrl, limit = 250) {
    const pageId = await this.extractPageId(pageIdOrUrl);
    const maxResults = Math.max(1, Math.min(Number(limit) || 250, 250));
    const children = [];
    let cursor = null;

    do {
      const remaining = Math.max(1, Math.min(maxResults - children.length, 250));
      const params = { limit: remaining };
      if (cursor) {
        params.cursor = cursor;
      }
      const response = await this.client.get(this.cloudV2Url(`/pages/${pageId}/children`), { params });
      const results = Array.isArray(response.data?.results) ? response.data.results : [];
      children.push(...results.map(page => this.normalizeV2ChildPage(page, pageId)));

      const next = response.data?._links?.next;
      cursor = next ? new URL(next, this.browserOrigin).searchParams.get('cursor') : null;
    } while (cursor && children.length < maxResults);

    return children;
  }

  /**
   * Get all descendant pages recursively
   */
  async getAllDescendantPages(pageId, maxDepth = 10, currentDepth = 0, options = {}) {
    if (typeof currentDepth === 'object' && currentDepth !== null) {
      options = currentDepth;
      currentDepth = 0;
    }
    const semaphore = createSemaphore(10);
    return this._collectDescendants(pageId, maxDepth, currentDepth, semaphore, options);
  }

  async getAllDescendantPagesV2(pageId, maxDepth = 10, currentDepth = 0) {
    if (typeof currentDepth === 'object' && currentDepth !== null) {
      currentDepth = 0;
    }
    const semaphore = createSemaphore(10);
    return this._collectDescendantsV2(pageId, maxDepth, currentDepth, semaphore);
  }

  async _collectDescendants(pageId, maxDepth, currentDepth, semaphore, options = {}) {
    if (currentDepth >= maxDepth) {
      return [];
    }

    await semaphore.acquire();
    let children;
    try {
      children = await this.getChildPages(pageId, 500, options);
    } finally {
      semaphore.release();
    }

    // Track depth for recursive JSON output while preserving direct parent linkage.
    const childrenWithDepth = children.map(child => ({
      ...child,
      parentId: child.parentId || String(pageId),
      depth: currentDepth + 1
    }));

    const grandChildrenLists = await Promise.all(
      children.map(child =>
        this._collectDescendants(child.id, maxDepth, currentDepth + 1, semaphore, options)
      )
    );

    return childrenWithDepth.concat(...grandChildrenLists);
  }

  async _collectDescendantsV2(pageId, maxDepth, currentDepth, semaphore) {
    if (currentDepth >= maxDepth) {
      return [];
    }

    await semaphore.acquire();
    let children;
    try {
      children = await this.getChildPagesV2(pageId, 250);
    } finally {
      semaphore.release();
    }

    const childrenWithDepth = children.map(child => ({
      ...child,
      parentId: child.parentId || String(pageId),
      depth: currentDepth + 1
    }));

    const grandChildrenLists = await Promise.all(
      children.map(child =>
        this._collectDescendantsV2(child.id, maxDepth, currentDepth + 1, semaphore)
      )
    );

    return childrenWithDepth.concat(...grandChildrenLists);
  }

  /**
   * Copy a page tree (page and all its descendants) to a new location
   */
  async copyPageTree(sourcePageId, targetParentId, newTitle = null, options = {}) {
    const {
      maxDepth = 10,
      excludePatterns = [],
      onProgress = null,
      quiet = false,
      delayMs = 100,
      copySuffix = ' (Copy)'
    } = options;

    // Get source page information
    const sourcePage = await this.getPageForEdit(sourcePageId);
    const sourceInfo = await this.getPageInfo(sourcePageId);
    
    // Determine new title
    const finalTitle = newTitle || `${sourcePage.title}${copySuffix}`;
    
    if (!quiet && onProgress) {
      onProgress(`Copying root: ${sourcePage.title} -> ${finalTitle}`);
    }

    // Create the root copied page
    const newRootPage = await this.createChildPage(
      finalTitle,
      sourceInfo.space.key,
      targetParentId,
      sourcePage.content,
      'storage'
    );

    if (!quiet && onProgress) {
      onProgress(`Root page created: ${newRootPage.title} (ID: ${newRootPage.id})`);
    }

    const result = {
      rootPage: newRootPage,
      copiedPages: [newRootPage],
      failures: [],
      totalCopied: 1,
    };

    // Precompile exclude patterns once for efficiency
    const compiledExclude = Array.isArray(excludePatterns)
      ? excludePatterns.filter(Boolean).map(p => this.globToRegExp(p))
      : [];

    await this.copyChildrenRecursive(
      sourcePageId,
      newRootPage.id,
      0,
      {
        spaceKey: sourceInfo.space.key,
        maxDepth,
        excludePatterns,
        compiledExclude,
        onProgress,
        quiet,
        delayMs,
      },
      result
    );

    result.totalCopied = result.copiedPages.length;
    return result;
  }

  /**
   * Build a tree structure from flat array of pages
   */
  buildPageTree(pages, rootPageId) {
    const pageMap = new Map();
    const tree = [];

    // Create nodes
    pages.forEach(page => {
      pageMap.set(page.id, { ...page, children: [] });
    });

    // Link by parentId if available; otherwise attach to root
    pages.forEach(page => {
      const node = pageMap.get(page.id);
      const parentId = page.parentId;
      if (parentId && pageMap.has(parentId)) {
        pageMap.get(parentId).children.push(node);
      } else if (parentId === rootPageId || !parentId) {
        tree.push(node);
      } else {
        // Parent not present in the list; treat as top-level under root
        tree.push(node);
      }
    });

    return tree;
  }

  /**
   * Recursively copy pages maintaining hierarchy
   */
  async copyChildrenRecursive(sourceParentId, targetParentId, currentDepth, opts, result) {
    const { spaceKey, maxDepth, excludePatterns, compiledExclude = [], onProgress, quiet, delayMs = 100 } = opts || {};

    if (currentDepth >= maxDepth) {
      return;
    }

    const children = await this.getChildPages(sourceParentId);
    for (let i = 0; i < children.length; i++) {
      const child = children[i];
      const patterns = (compiledExclude && compiledExclude.length) ? compiledExclude : excludePatterns;
      if (this.shouldExcludePage(child.title, patterns)) {
        if (!quiet && onProgress) {
          onProgress(`Skipped: ${child.title}`);
        }
        continue;
      }

      if (!quiet && onProgress) {
        onProgress(`Copying: ${child.title}`);
      }

      try {
        // Fetch full content to ensure complete copy
        const fullChild = await this.getPageForEdit(child.id);
        const newPage = await this.createChildPage(
          fullChild.title,
          spaceKey,
          targetParentId,
          fullChild.content,
          'storage'
        );

        result.copiedPages.push(newPage);
        if (!quiet && onProgress) {
          onProgress(`Created: ${newPage.title} (ID: ${newPage.id})`);
        }

        // Rate limiting safety: only pause between siblings
        if (delayMs > 0 && i < children.length - 1) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }

        // Recurse into this child's subtree
        await this.copyChildrenRecursive(child.id, newPage.id, currentDepth + 1, opts, result);
      } catch (error) {
        if (!quiet && onProgress) {
          const status = error?.response?.status;
          const statusText = error?.response?.statusText;
          const msg = status ? `${status} ${statusText || ''}`.trim() : error.message;
          onProgress(`Failed: ${child.title} - ${msg}`);
        }
        result.failures.push({
          id: child.id,
          title: child.title,
          error: error.message,
          status: error?.response?.status || null
        });
        // Continue with other pages (do not throw)
        continue;
      }
    }
  }

  /**
   * Convert a simple glob pattern to a safe RegExp
   * Supports '*' → '.*' and '?' → '.', escapes other regex metacharacters.
   */
  globToRegExp(pattern, flags = 'i') {
    // Escape regex special characters: . + ^ $ { } ( ) | [ ] \
    // Note: backslash must be escaped properly in string and class contexts
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    const regexPattern = escaped
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    return new RegExp(`^${regexPattern}$`, flags);
  }

  /**
   * Check if a page should be excluded based on patterns
   */
  shouldExcludePage(title, excludePatterns) {
    if (!excludePatterns || excludePatterns.length === 0) {
      return false;
    }

    return excludePatterns.some(pattern => {
      if (pattern instanceof RegExp) return pattern.test(title);
      return this.globToRegExp(pattern).test(title);
    });
  }

  matchesPattern(value, patterns) {
    if (!patterns) {
      return true;
    }

    const list = Array.isArray(patterns) ? patterns.filter(Boolean) : [patterns];
    if (list.length === 0) {
      return true;
    }

    return list.some((pattern) => this.globToRegExp(pattern).test(value));
  }

  normalizeAttachment(raw) {
    return {
      id: raw.id,
      title: raw.title,
      mediaType: raw.metadata?.mediaType || raw.mediaType || raw.type || '',
      fileSize: raw.extensions?.fileSize || raw.fileSize || 0,
      version: raw.version?.number || 1,
      downloadLink: this.toAbsoluteUrl(raw._links?.download || raw.downloadLink)
    };
  }

  normalizeUser(user) {
    if (!user) {
      return null;
    }

    return {
      displayName: user.displayName || user.publicName || user.username || user.userKey || user.accountId || 'Unknown',
      accountId: user.accountId,
      userKey: user.userKey,
      username: user.username,
      email: user.email
    };
  }

  normalizeAncestors(rawAncestors = []) {
    if (!Array.isArray(rawAncestors)) {
      return [];
    }

    return rawAncestors.map((ancestor) => {
      const id = ancestor?.id ?? ancestor;
      return {
        id: id !== undefined && id !== null ? String(id) : null,
        type: ancestor?.type || null,
        title: ancestor?.title || null
      };
    }).filter((ancestor) => ancestor.id);
  }

  normalizeSpace(space) {
    if (!space) {
      return null;
    }

    return {
      key: space.key || null,
      name: space.name || null
    };
  }

  getPageParentId(ancestors = []) {
    if (!Array.isArray(ancestors) || ancestors.length === 0) {
      return null;
    }

    return ancestors[ancestors.length - 1].id || null;
  }

  normalizePage(raw, overrides = {}) {
    const space = overrides.space === undefined
      ? this.normalizeSpace(raw?.space)
      : this.normalizeSpace(overrides.space);
    const ancestors = overrides.ancestors || this.normalizeAncestors(raw?.ancestors);
    const spaceKey = overrides.spaceKey || space?.key || null;
    const id = raw?.id !== undefined && raw?.id !== null ? String(raw.id) : null;
    const webui = raw?._links?.webui || null;
    const linksBase = raw?._links?.base || null;
    const fallbackUrl = (spaceKey && id)
      ? `${this.webUrlPrefix}/spaces/${spaceKey}/pages/${id}`
      : null;

    return {
      id,
      title: raw?.title || '',
      type: raw?.type || null,
      status: raw?.status || null,
      space,
      spaceKey,
      parentId: overrides.parentId === undefined
        ? this.getPageParentId(ancestors)
        : (overrides.parentId === null ? null : String(overrides.parentId)),
      version: overrides.version !== undefined ? overrides.version : (raw?.version?.number || null),
      url: overrides.url || this.toAbsoluteUrl(webui, linksBase) || (fallbackUrl ? this.buildUrl(fallbackUrl) : null),
      ancestors,
      depth: overrides.depth,
      author: overrides.author !== undefined ? overrides.author : this.normalizeUser(raw?.history?.createdBy),
      lastUpdatedBy: overrides.lastUpdatedBy !== undefined ? overrides.lastUpdatedBy : this.normalizeUser(raw?.version?.by),
      createdAt: overrides.createdAt !== undefined ? overrides.createdAt : (raw?.history?.createdDate || null),
      updatedAt: overrides.updatedAt !== undefined ? overrides.updatedAt : (raw?.version?.when || null)
    };
  }

  buildUrl(path) {
    const normalized = path && !path.startsWith('/') ? `/${path}` : (path || '');
    return `${this.browserOrigin}${normalized}`;
  }

  configuredOrigin() {
    if (!this.domain && !this.oauth?.cloudId) {
      return null;
    }
    if (this.authType === 'oauth') {
      return 'https://api.atlassian.com';
    }
    try {
      return new URL(`${this.protocol}://${this.domain}`).origin;
    } catch {
      return null;
    }
  }

  isSameOriginAsConfigured(url) {
    const expected = this.configuredOrigin();
    if (!url || !expected) {
      return false;
    }
    try {
      const actual = new URL(url).origin;
      if (actual === expected) {
        return true;
      }
      if (this.authType === 'oauth' && this.browserOrigin) {
        return actual === new URL(this.browserOrigin).origin;
      }
      return false;
    } catch {
      return false;
    }
  }

  assertSameOrigin(url) {
    if (this.isSameOriginAsConfigured(url)) {
      return;
    }
    let actualOrigin;
    try {
      actualOrigin = new URL(url).origin;
    } catch {
      actualOrigin = String(url);
    }
    const expectedOrigin = this.configuredOrigin() ?? `${this.protocol}://${this.domain}`;
    throw new Error(
      `Refusing to send credentials to "${actualOrigin}": origin does not match the configured Confluence origin "${expectedOrigin}". This may indicate a tampered or misconfigured API response, or an http downgrade against an https-configured client.`
    );
  }

  joinBaseUrl(baseUrl, path) {
    if (!baseUrl) {
      return null;
    }

    const normalizedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    const normalizedPath = path.startsWith('/') ? path : `/${path}`;
    return `${normalizedBase}${normalizedPath}`;
  }

  toAbsoluteUrl(pathOrUrl, baseUrl = null) {
    if (!pathOrUrl) {
      return null;
    }

    if (pathOrUrl.startsWith('http://') || pathOrUrl.startsWith('https://')) {
      return pathOrUrl;
    }

    if (baseUrl) {
      return this.joinBaseUrl(baseUrl, pathOrUrl);
    }

    const pathWithPrefix = this.webUrlPrefix && !pathOrUrl.startsWith(this.webUrlPrefix)
      ? `${this.webUrlPrefix}${pathOrUrl}`
      : pathOrUrl;
    return this.buildUrl(pathWithPrefix);
  }

  parseNextStart(nextLink) {
    if (!nextLink) {
      return null;
    }

    const match = nextLink.match(/[?&]start=(\d+)/);
    if (!match) {
      return null;
    }

    const value = parseInt(match[1], 10);
    return Number.isNaN(value) ? null : value;
  }

  parseNextCursor(nextLink) {
    if (!nextLink) {
      return null;
    }

    try {
      return new URL(nextLink, this.browserOrigin).searchParams.get('cursor');
    } catch {
      const match = nextLink.match(/[?&]cursor=([^&]+)/);
      return match ? decodeURIComponent(match[1]) : null;
    }
  }

  parsePositiveInt(value, fallback) {
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed < 0) {
      return fallback;
    }
    return parsed;
  }
}

ConfluenceClient.createLocalConverter = function () {
  const instance = Object.create(ConfluenceClient.prototype);
  instance.converter = new MacroConverter();
  instance.markdown = instance.converter.markdown;
  return instance;
};

module.exports = ConfluenceClient;
module.exports.NAMED_ENTITIES = NAMED_ENTITIES;
