const fs = require('fs');
const path = require('path');
const os = require('os');
const inquirer = require('inquirer');
const chalk = require('chalk');

const CONFIG_DIR = path.join(os.homedir(), '.confluence-cli');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const DEFAULT_PROFILE = 'default';

const AUTH_CHOICES = [
  { name: 'Basic (credentials)', value: 'basic' },
  { name: 'Bearer token', value: 'bearer' },
  { name: 'OAuth 2.0 (Atlassian Cloud)', value: 'oauth' },
  { name: 'Client certificate (mTLS)', value: 'mtls' },
  { name: 'Cookie (Enterprise SSO)', value: 'cookie' }
];

const AUTH_TYPES = ['basic', 'bearer', 'oauth', 'mtls', 'cookie'];

const { VALID_LINK_STYLES } = require('./macro-converter');

const normalizeLinkStyle = (rawValue, source) => {
  if (rawValue === undefined || rawValue === null || rawValue === '') {
    return undefined;
  }
  const value = String(rawValue).trim().toLowerCase();
  if (VALID_LINK_STYLES.includes(value)) {
    return value;
  }
  const label = source ? `${source} ` : '';
  console.error(chalk.yellow(
    `⚠ Invalid linkStyle ${label}"${rawValue}"; valid values: ${VALID_LINK_STYLES.join(', ')}. Falling back to auto-detection.`
  ));
  return undefined;
};

const isValidProfileName = (name) => /^[a-zA-Z0-9_-]+$/.test(name);

const requiredInput = (label) => (input) => {
  if (!input || !input.trim()) {
    return `${label} is required`;
  }
  return true;
};

const PROTOCOL_CHOICES = [
  { name: 'HTTPS (recommended)', value: 'https' },
  { name: 'HTTP', value: 'http' }
];

const normalizeProtocol = (rawValue) => {
  const normalized = (rawValue || '').trim().toLowerCase();
  if (normalized === 'http' || normalized === 'https') {
    return normalized;
  }
  return 'https';
};

const normalizeAuthType = (rawValue, hasEmail) => {
  const normalized = (rawValue || '').trim().toLowerCase();
  if (AUTH_TYPES.includes(normalized)) {
    return normalized;
  }
  return hasEmail ? 'basic' : 'bearer';
};

const trimOptional = (value) => {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
};

const normalizeOAuthConfig = (oauth = {}) => {
  const normalized = {
    clientId: trimOptional(oauth.clientId),
    clientSecret: trimOptional(oauth.clientSecret),
    accessToken: trimOptional(oauth.accessToken || oauth.token),
    refreshToken: trimOptional(oauth.refreshToken),
    cloudId: trimOptional(oauth.cloudId),
    siteUrl: trimOptional(oauth.siteUrl),
    expiresAt: oauth.expiresAt !== undefined && oauth.expiresAt !== null && oauth.expiresAt !== ''
      ? Number(oauth.expiresAt)
      : undefined,
    scopes: Array.isArray(oauth.scopes)
      ? oauth.scopes.map(scope => String(scope).trim()).filter(Boolean)
      : (typeof oauth.scopes === 'string'
        ? oauth.scopes.split(/[,\s]+/).map(scope => scope.trim()).filter(Boolean)
        : undefined)
  };

  Object.keys(normalized).forEach((key) => {
    if (normalized[key] === undefined || normalized[key] === null || normalized[key] === '') {
      delete normalized[key];
    }
  });

  return Object.keys(normalized).length > 0 ? normalized : undefined;
};

const normalizeMtlsConfig = (mtls) => {
  if (!mtls) {
    return undefined;
  }

  const normalized = {
    caCert: trimOptional(mtls.caCert),
    clientCert: trimOptional(mtls.clientCert),
    clientKey: trimOptional(mtls.clientKey),
  };

  if (!normalized.caCert && !normalized.clientCert && !normalized.clientKey) {
    return undefined;
  }

  return normalized;
};

const validateMtlsConfig = (mtls, labelPrefix = 'mTLS') => {
  const normalized = normalizeMtlsConfig(mtls);
  if (!normalized) {
    return [`${labelPrefix} requires a client certificate and client key.`];
  }

  const errors = [];
  if (!normalized.clientCert) {
    errors.push(`${labelPrefix} requires a client certificate.`);
  } else if (!fs.existsSync(normalized.clientCert)) {
    errors.push(`${labelPrefix} client certificate file not found: ${normalized.clientCert}`);
  }
  if (!normalized.clientKey) {
    errors.push(`${labelPrefix} requires a client key.`);
  } else if (!fs.existsSync(normalized.clientKey)) {
    errors.push(`${labelPrefix} client key file not found: ${normalized.clientKey}`);
  }
  if (normalized.caCert && !fs.existsSync(normalized.caCert)) {
    errors.push(`${labelPrefix} CA certificate file not found: ${normalized.caCert}`);
  }
  return errors;
};

const validateMtlsProtocol = (protocol) => {
  if (normalizeProtocol(protocol) === 'http') {
    return 'mTLS authentication requires HTTPS and is not compatible with HTTP.';
  }
  return null;
};

// Validate a resolved auth configuration (post-normalization).
// Returns error messages only; callers format source-specific hints.
const validateAuthConfig = (auth, mtlsSourceLabel) => {
  const errors = [];

  if (auth.authType === 'basic' && !auth.email) {
    errors.push('Basic authentication requires an email address or username.');
  }

  if (auth.authType === 'cookie' && !auth.cookie) {
    errors.push('Cookie authentication requires a cookie value.');
  }

  if (auth.authType === 'oauth') {
    const oauth = normalizeOAuthConfig(auth.oauth || auth);
    if (!oauth || (!oauth.accessToken && !oauth.refreshToken)) {
      errors.push('OAuth authentication requires an access token or refresh token.');
    }
    if (!oauth || !oauth.cloudId) {
      errors.push('OAuth authentication requires a Confluence Cloud ID.');
    }
    if (oauth?.refreshToken && (!oauth.clientId || !oauth.clientSecret)) {
      errors.push('OAuth refresh requires a client ID and client secret.');
    }
  } else if (auth.authType !== 'mtls' && auth.authType !== 'cookie' && !auth.token) {
    errors.push('Bearer or basic authentication requires a token.');
  }

  if (auth.authType === 'mtls') {
    errors.push(...validateMtlsConfig(auth.mtls, mtlsSourceLabel));
    const protocolError = validateMtlsProtocol(auth.protocol);
    if (protocolError) {
      errors.push(protocolError);
    }
  }

  return errors;
};

/**
 * Build an inquirer question for an mTLS file path prompt.
 * @param {string} name       - answer key (e.g. 'tlsClientCert')
 * @param {string} message    - prompt text
 * @param {boolean} required  - whether the field is mandatory
 * @param {Function} [whenFn] - optional custom `when` predicate; defaults to authType === 'mtls'
 */
const mtlsCertQuestion = (name, message, required, whenFn) => ({
  type: 'input',
  name,
  message,
  when: whenFn || ((responses) => responses.authType === 'mtls'),
  validate: (input) => {
    const value = (input || '').trim();
    if (!value) {
      return required ? `${message.replace(/:$/, '')} is required for mTLS.` : true;
    }
    if (!fs.existsSync(value)) {
      return `File not found: ${value}`;
    }
    return true;
  }
});

const inferApiPath = (domain) => {
  if (!domain) {
    return '/rest/api';
  }

  const normalizedDomain = domain.trim().toLowerCase();
  if (normalizedDomain.endsWith('.atlassian.net')) {
    return '/wiki/rest/api';
  }

  return '/rest/api';
};

const normalizeApiPath = (rawValue, domain) => {
  const trimmed = (rawValue || '').trim();

  if (!trimmed) {
    return inferApiPath(domain);
  }

  if (!trimmed.startsWith('/')) {
    throw new Error('Confluence API path must start with "/".');
  }

  const withoutTrailing = trimmed.replace(/\/+$/, '');
  return withoutTrailing || inferApiPath(domain);
};

// Read config file with backward compatibility for old flat format
function readConfigFile() {
  if (!fs.existsSync(CONFIG_FILE)) {
    return null;
  }

  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));

    // Detect old flat format (has domain at top level, no profiles key)
    if (raw.domain && !raw.profiles) {
      const profile = {
        domain: raw.domain,
        protocol: raw.protocol,
        apiPath: raw.apiPath,
        token: raw.token,
        authType: raw.authType
      };
      const mtls = normalizeMtlsConfig(raw.mtls);
      if (mtls) {
        profile.mtls = mtls;
      }
      if (raw.email) {
        profile.email = raw.email;
      }
      if (raw.cookie) {
        profile.cookie = raw.cookie;
      }
      return {
        activeProfile: DEFAULT_PROFILE,
        profiles: { [DEFAULT_PROFILE]: profile }
      };
    }

    return raw;
  } catch (error) {
    console.error(chalk.yellow(`⚠ Failed to parse config file at ${CONFIG_FILE}: ${error.message}`));
    console.error(chalk.yellow('  Run "confluence init" to recreate it.'));
    return null;
  }
}

// Write the full multi-profile config structure
function saveConfigFile(data) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  } else {
    fs.chmodSync(CONFIG_DIR, 0o700);
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.chmodSync(CONFIG_FILE, 0o600);
}

// Helper function to validate CLI-provided options
const validateCliOptions = (options) => {
  const errors = [];

  if (options.domain && (typeof options.domain !== 'string' || !options.domain.trim())) {
    errors.push('--domain cannot be empty');
  }

  if (options.token !== undefined && (typeof options.token !== 'string' || !options.token.trim())) {
    errors.push('--token cannot be empty');
  }

  if (options.email && (typeof options.email !== 'string' || !options.email.trim())) {
    errors.push('--email cannot be empty');
  }

  if (options.apiPath) {
    if (typeof options.apiPath !== 'string' || !options.apiPath.startsWith('/')) {
      errors.push('--api-path must start with "/"');
    } else {
      // Validate API path format
      try {
        normalizeApiPath(options.apiPath, options.domain || 'example.com');
      } catch (error) {
        errors.push(`--api-path is invalid: ${error.message}`);
      }
    }
  }

  if (options.protocol && (typeof options.protocol !== 'string' || !['http', 'https'].includes(options.protocol.toLowerCase()))) {
    errors.push('--protocol must be "http" or "https"');
  }

  if (options.authType && (typeof options.authType !== 'string' || !AUTH_TYPES.includes(options.authType.toLowerCase()))) {
    errors.push('--auth-type must be "basic", "bearer", "oauth", "mtls", or "cookie"');
  }

  // Check if basic auth is provided with email
  const normAuthType = (typeof options.authType === 'string' && options.authType)
    ? normalizeAuthType(options.authType, Boolean(options.email))
    : null;
  if (normAuthType === 'basic' && !options.email) {
    errors.push('--email is required when using basic authentication (use your username for on-premise)');
  }

  if (normAuthType === 'mtls') {
    validateMtlsConfig(options.mtls, '--auth-type mtls').forEach((error) => {
      errors.push(error);
    });
    const protocolError = validateMtlsProtocol(options.protocol);
    if (protocolError) {
      errors.push(protocolError);
    }
  }

  if (normAuthType === 'cookie' && options.cookie !== undefined && (typeof options.cookie !== 'string' || !options.cookie.trim())) {
    errors.push('--cookie cannot be empty when using cookie authentication');
  }

  if (normAuthType === 'oauth') {
    const oauth = normalizeOAuthConfig(options.oauth || options);
    if (!oauth || (!oauth.accessToken && !oauth.refreshToken)) {
      errors.push('--oauth-access-token or --oauth-refresh-token is required when using OAuth authentication');
    }
    if (!oauth || !oauth.cloudId) {
      errors.push('--oauth-cloud-id is required when using OAuth authentication');
    }
  }

  return errors;
};

// Helper function to save configuration with validation
const saveConfig = (configData, profileName) => {
  const config = {
    domain: configData.domain.trim(),
    protocol: normalizeProtocol(configData.protocol),
    apiPath: normalizeApiPath(configData.apiPath, configData.domain),
    authType: configData.authType
  };

  if (configData.token) {
    config.token = configData.token.trim();
  }

  const oauth = normalizeOAuthConfig(configData.oauth || configData);
  if (configData.authType === 'oauth' && oauth) {
    config.oauth = oauth;
  }

  if (configData.authType === 'basic' && configData.email) {
    config.email = configData.email.trim();
  }

  if (configData.authType === 'cookie' && configData.cookie) {
    config.cookie = configData.cookie.trim();
  }

  const mtls = normalizeMtlsConfig(configData.mtls);
  if (mtls) {
    config.mtls = mtls;
  }

  if (configData.readOnly) {
    config.readOnly = true;
  }

  // Read existing config file (or create new structure)
  const fileData = readConfigFile() || { activeProfile: DEFAULT_PROFILE, profiles: {} };

  const targetProfile = profileName || fileData.activeProfile || DEFAULT_PROFILE;
  fileData.profiles[targetProfile] = config;

  // If this is the first profile, make it active
  if (!fileData.activeProfile || !fileData.profiles[fileData.activeProfile]) {
    fileData.activeProfile = targetProfile;
  }

  saveConfigFile(fileData);

  console.log(chalk.green('✅ Configuration saved successfully!'));
  if (profileName) {
    console.log(`Profile: ${chalk.cyan(targetProfile)}`);
  }
  console.log(`Config file location: ${chalk.gray(CONFIG_FILE)}`);
  console.log(chalk.yellow('\n💡 Tip: You can regenerate this config anytime by running "confluence init"'));
};

function saveOAuthConfig(configData, profileName) {
  saveConfig({
    ...configData,
    authType: 'oauth',
    protocol: configData.protocol || 'https',
    apiPath: configData.apiPath || '/wiki/rest/api',
    oauth: normalizeOAuthConfig(configData.oauth || configData)
  }, profileName);
}

function updateOAuthTokens(profileName, oauthUpdates) {
  if (!profileName) {
    return false;
  }
  const fileData = readConfigFile();
  if (!fileData?.profiles?.[profileName]) {
    return false;
  }
  const profile = fileData.profiles[profileName];
  const existing = normalizeOAuthConfig(profile.oauth || profile) || {};
  profile.oauth = normalizeOAuthConfig({ ...existing, ...oauthUpdates });
  saveConfigFile(fileData);
  return true;
}

function clearOAuthTokens(profileName) {
  const fileData = readConfigFile();
  const targetProfile = profileName || fileData?.activeProfile || DEFAULT_PROFILE;
  if (!fileData?.profiles?.[targetProfile]) {
    return false;
  }
  const profile = fileData.profiles[targetProfile];
  if (profile.oauth) {
    delete profile.oauth.accessToken;
    delete profile.oauth.refreshToken;
    delete profile.oauth.expiresAt;
  }
  saveConfigFile(fileData);
  return true;
}

// Helper function to prompt for missing values
const promptForMissingValues = async (providedValues) => {
  const questions = [];

  // Protocol question
  if (!providedValues.protocol) {
    questions.push({
      type: 'list',
      name: 'protocol',
      message: 'Protocol:',
      choices: PROTOCOL_CHOICES,
      default: 'https'
    });
  }

  // Domain question
  if (!providedValues.domain) {
    questions.push({
      type: 'input',
      name: 'domain',
      message: 'Confluence domain (e.g., yourcompany.atlassian.net):',
      validate: requiredInput('Domain')
    });
  }

  // API Path question
  if (!providedValues.apiPath) {
    questions.push({
      type: 'input',
      name: 'apiPath',
      message: 'REST API path (Cloud: /wiki/rest/api, Server: /rest/api):',
      default: (responses) => inferApiPath(providedValues.domain || responses.domain),
      validate: (input, responses) => {
        const value = (input || '').trim();
        if (!value) {
          return true;
        }
        if (!value.startsWith('/')) {
          return 'API path must start with "/"';
        }
        try {
          const domain = providedValues.domain || responses.domain;
          normalizeApiPath(value, domain);
          return true;
        } catch (error) {
          return error.message;
        }
      }
    });
  }

  // Auth Type question
  const hasEmail = Boolean(providedValues.email);
  if (!providedValues.authType) {
    questions.push({
      type: 'list',
      name: 'authType',
      message: 'Authentication method:',
      choices: AUTH_CHOICES,
      default: hasEmail ? 'basic' : 'bearer'
    });
  }

  // Email question (conditional on authType)
  if (!providedValues.email) {
    questions.push({
      type: 'input',
      name: 'email',
      message: 'Email / username:',
      when: (responses) => {
        const authType = providedValues.authType || responses.authType;
        return authType === 'basic';
      },
      validate: requiredInput('Email / username')
    });
  }

  // Token question
  if (!providedValues.token) {
    questions.push({
      type: 'password',
      name: 'token',
      message: 'API token / password:',
      when: (responses) => {
        const authType = providedValues.authType || responses.authType;
        return authType !== 'mtls' && authType !== 'cookie' && authType !== 'oauth';
      },
      validate: requiredInput('API token / password')
    });
  }

  // Cookie question (Enterprise SSO)
  if (!providedValues.cookie) {
    questions.push({
      type: 'password',
      name: 'cookie',
      message: 'Cookie (format: "name=value" or "name=value; name2=value2"):',
      when: (responses) => {
        const authType = providedValues.authType || responses.authType;
        return authType === 'cookie';
      },
      validate: requiredInput('Cookie')
    });
  }

  // mTLS certificate path questions
  const mtls = normalizeMtlsConfig(providedValues.mtls);
  const mtlsWhen = (responses) => {
    const authType = providedValues.authType || responses.authType;
    return authType === 'mtls';
  };
  if (!mtls || !mtls.clientCert) {
    questions.push(mtlsCertQuestion('tlsClientCert', 'Path to client certificate file (PEM):', true, mtlsWhen));
  }
  if (!mtls || !mtls.clientKey) {
    questions.push(mtlsCertQuestion('tlsClientKey', 'Path to client key file (PEM):', true, mtlsWhen));
  }
  if (!mtls || !mtls.caCert) {
    questions.push(mtlsCertQuestion('tlsCaCert', 'Path to CA certificate file (PEM, optional):', false, mtlsWhen));
  }

  if (questions.length === 0) {
    return providedValues;
  }

  const answers = await inquirer.prompt(questions);
  return { ...providedValues, ...answers };
};

async function initConfig(cliOptions = {}) {
  const profileName = cliOptions.profile;

  // Validate profile name if provided
  if (profileName && !isValidProfileName(profileName)) {
    console.error(chalk.red('❌ Invalid profile name. Use only letters, numbers, hyphens, and underscores.'));
    process.exit(1);
  }

  const readOnly = cliOptions.readOnly || false;

  // Extract provided values from CLI options.
  // Normalize authType up front so downstream case-insensitive checks
  // (hasRequiredValues, prompt `when` predicates) work for values like
  // `--auth-type COOKIE` or `--auth-type MTLS`.
  const providedValues = {
    protocol: cliOptions.protocol,
    domain: cliOptions.domain,
    apiPath: cliOptions.apiPath,
    authType: (typeof cliOptions.authType === 'string' && cliOptions.authType)
      ? cliOptions.authType.trim().toLowerCase()
      : cliOptions.authType,
    email: cliOptions.email,
    token: cliOptions.token,
    cookie: cliOptions.cookie,
    oauth: {
      clientId: cliOptions.oauthClientId,
      clientSecret: cliOptions.oauthClientSecret,
      accessToken: cliOptions.oauthAccessToken,
      refreshToken: cliOptions.oauthRefreshToken,
      expiresAt: cliOptions.oauthExpiresAt,
      cloudId: cliOptions.oauthCloudId,
      siteUrl: cliOptions.oauthSiteUrl,
      scopes: cliOptions.oauthScopes,
    },
    mtls: cliOptions.mtls || {
      caCert: cliOptions.tlsCaCert,
      clientCert: cliOptions.tlsClientCert,
      clientKey: cliOptions.tlsClientKey,
    }
  };

  // Check if any CLI options were provided
  const hasCliOptions = Object.values(providedValues).some(v => v);

  if (!hasCliOptions) {
    // Interactive mode: no CLI options provided
    console.log(chalk.blue('🚀 Confluence CLI Configuration'));
    if (profileName) {
      console.log(`Profile: ${chalk.cyan(profileName)}`);
    }
    console.log('Please provide your Confluence connection details:\n');

    const answers = await inquirer.prompt([
      {
        type: 'list',
        name: 'protocol',
        message: 'Protocol:',
        choices: PROTOCOL_CHOICES,
        default: 'https'
      },
      {
        type: 'input',
        name: 'domain',
        message: 'Confluence domain (e.g., yourcompany.atlassian.net):',
        validate: requiredInput('Domain')
      },
      {
        type: 'input',
        name: 'apiPath',
        message: 'REST API path (Cloud: /wiki/rest/api, Server: /rest/api):',
        default: (responses) => inferApiPath(responses.domain),
        validate: (input, responses) => {
          const value = (input || '').trim();
          if (!value) {
            return true;
          }
          if (!value.startsWith('/')) {
            return 'API path must start with "/"';
          }
          try {
            normalizeApiPath(value, responses.domain);
            return true;
          } catch (error) {
            return error.message;
          }
        }
      },
      {
        type: 'list',
        name: 'authType',
        message: 'Authentication method:',
        choices: AUTH_CHOICES,
        default: 'basic'
      },
      {
        type: 'input',
        name: 'email',
        message: 'Email / username:',
        when: (responses) => responses.authType === 'basic',
        validate: requiredInput('Email / username')
      },
      {
        type: 'password',
        name: 'token',
        message: 'API token / password:',
        when: (responses) => responses.authType !== 'mtls' && responses.authType !== 'cookie' && responses.authType !== 'oauth',
        validate: requiredInput('API token / password')
      },
      {
        type: 'password',
        name: 'cookie',
        message: 'Cookie (format: "name=value" or "name=value; name2=value2"):',
        when: (responses) => responses.authType === 'cookie',
        validate: requiredInput('Cookie')
      },
      mtlsCertQuestion('tlsClientCert', 'Path to client certificate file (PEM):', true),
      mtlsCertQuestion('tlsClientKey', 'Path to client key file (PEM):', true),
      mtlsCertQuestion('tlsCaCert', 'Path to CA certificate file (PEM, optional):', false)
    ]);

    const configData = { ...answers, readOnly };
    if (answers.authType === 'mtls') {
      configData.mtls = {
        clientCert: answers.tlsClientCert,
        clientKey: answers.tlsClientKey,
        caCert: answers.tlsCaCert || undefined,
      };
    }

    saveConfig(configData, profileName);
    return;
  }

  // Non-interactive or hybrid mode: CLI options provided
  // Validate provided options
  const validationErrors = validateCliOptions(providedValues);
  if (validationErrors.length > 0) {
    console.error(chalk.red('❌ Configuration Error:'));
    validationErrors.forEach(error => {
      console.error(chalk.red(`  • ${error}`));
    });
    process.exit(1);
  }

  // Check if all required values are provided for non-interactive mode
  // Non-interactive requires: domain, and one of:
  //   - authType === 'mtls' (certs via flags/env)
  //   - authType === 'cookie' + cookie
  //   - token + (authType or email) for basic/bearer
  const hasRequiredValues = Boolean(
    providedValues.domain &&
    (
      providedValues.authType === 'mtls'
      || (providedValues.authType === 'cookie' && providedValues.cookie)
      || (
        providedValues.authType === 'oauth' &&
        normalizeOAuthConfig(providedValues.oauth)?.cloudId &&
        (
          normalizeOAuthConfig(providedValues.oauth)?.accessToken ||
          normalizeOAuthConfig(providedValues.oauth)?.refreshToken
        )
      )
      || (
        providedValues.token &&
        (providedValues.authType || providedValues.email)
      )
    )
  );

  if (hasRequiredValues) {
    // Non-interactive mode: all required values provided
    try {
      // Infer authType if not provided
      let inferredAuthType = providedValues.authType;
      if (!inferredAuthType) {
        inferredAuthType = providedValues.email ? 'basic' : 'bearer';
      }

      const normalizedAuthType = normalizeAuthType(inferredAuthType, Boolean(providedValues.email));
      const normalizedDomain = providedValues.domain.trim();

      // Verify basic auth has email
      if (normalizedAuthType === 'basic' && !providedValues.email) {
        console.error(chalk.red('❌ Email is required for basic authentication'));
        process.exit(1);
      }

      if (normalizedAuthType !== 'mtls' && normalizedAuthType !== 'cookie' && normalizedAuthType !== 'oauth' && !providedValues.token) {
        console.error(chalk.red('❌ Token is required for basic or bearer authentication'));
        process.exit(1);
      }

      const normalizedOAuth = normalizeOAuthConfig(providedValues.oauth);
      if (normalizedAuthType === 'oauth' && (!normalizedOAuth || (!normalizedOAuth.accessToken && !normalizedOAuth.refreshToken))) {
        console.error(chalk.red('❌ OAuth access token or refresh token is required'));
        process.exit(1);
      }

      if (normalizedAuthType === 'cookie' && !providedValues.cookie) {
        console.error(chalk.red('❌ Cookie is required for cookie authentication'));
        process.exit(1);
      }

      // Verify API path format if provided
      if (providedValues.apiPath) {
        normalizeApiPath(providedValues.apiPath, normalizedDomain);
      }

      const configData = {
        domain: normalizedDomain,
        protocol: normalizeProtocol(providedValues.protocol),
        apiPath: providedValues.apiPath || inferApiPath(normalizedDomain),
        token: providedValues.token,
        authType: normalizedAuthType,
        email: providedValues.email,
        cookie: providedValues.cookie,
        oauth: normalizedOAuth,
        mtls: providedValues.mtls,
        readOnly
      };

      saveConfig(configData, profileName);
    } catch (error) {
      console.error(chalk.red(`❌ ${error.message}`));
      process.exit(1);
    }
    return;
  }

  // Hybrid mode: some values provided, prompt for the rest
  try {
    console.log(chalk.blue('🚀 Confluence CLI Configuration'));
    if (profileName) {
      console.log(`Profile: ${chalk.cyan(profileName)}`);
    }
    console.log('Completing configuration with interactive prompts:\n');

    const mergedValues = await promptForMissingValues(providedValues);

    // Normalize auth type
    mergedValues.authType = normalizeAuthType(mergedValues.authType, Boolean(mergedValues.email));

    // Build mTLS config from prompted values if needed
    if (mergedValues.authType === 'mtls') {
      mergedValues.mtls = normalizeMtlsConfig({
        clientCert: mergedValues.tlsClientCert || (mergedValues.mtls && mergedValues.mtls.clientCert),
        clientKey: mergedValues.tlsClientKey || (mergedValues.mtls && mergedValues.mtls.clientKey),
        caCert: mergedValues.tlsCaCert || (mergedValues.mtls && mergedValues.mtls.caCert),
      });
    }

    saveConfig({ ...mergedValues, readOnly }, profileName);
  } catch (error) {
    console.error(chalk.red(`❌ ${error.message}`));
    process.exit(1);
  }
}

function getConfig(profileName) {
  const envDomain = process.env.CONFLUENCE_DOMAIN || process.env.CONFLUENCE_HOST;
  const envToken = process.env.CONFLUENCE_API_TOKEN || process.env.CONFLUENCE_PASSWORD;
  const envEmail = process.env.CONFLUENCE_EMAIL || process.env.CONFLUENCE_USERNAME;
  // Normalize up front so env gating and inferredAuthType are case-insensitive
  // for values like CONFLUENCE_AUTH_TYPE=COOKIE / MTLS.
  const envAuthType = process.env.CONFLUENCE_AUTH_TYPE
    ? process.env.CONFLUENCE_AUTH_TYPE.trim().toLowerCase()
    : undefined;
  const envApiPath = process.env.CONFLUENCE_API_PATH;
  const envProtocol = process.env.CONFLUENCE_PROTOCOL;
  const envReadOnly = process.env.CONFLUENCE_READ_ONLY;
  const envForceCloud = process.env.CONFLUENCE_FORCE_CLOUD;
  const envLinkStyle = normalizeLinkStyle(process.env.CONFLUENCE_LINK_STYLE, 'from CONFLUENCE_LINK_STYLE');
  const envCookie = process.env.CONFLUENCE_COOKIE;
  const envOAuth = normalizeOAuthConfig({
    clientId: process.env.CONFLUENCE_OAUTH_CLIENT_ID,
    clientSecret: process.env.CONFLUENCE_OAUTH_CLIENT_SECRET,
    accessToken: process.env.CONFLUENCE_OAUTH_ACCESS_TOKEN || (envAuthType === 'oauth' ? envToken : undefined),
    refreshToken: process.env.CONFLUENCE_OAUTH_REFRESH_TOKEN,
    expiresAt: process.env.CONFLUENCE_OAUTH_EXPIRES_AT,
    cloudId: process.env.CONFLUENCE_CLOUD_ID || process.env.CONFLUENCE_OAUTH_CLOUD_ID,
    siteUrl: process.env.CONFLUENCE_OAUTH_SITE_URL,
    scopes: process.env.CONFLUENCE_OAUTH_SCOPES,
  });
  const envMtls = normalizeMtlsConfig({
    caCert: process.env.CONFLUENCE_TLS_CA_CERT,
    clientCert: process.env.CONFLUENCE_TLS_CLIENT_CERT,
    clientKey: process.env.CONFLUENCE_TLS_CLIENT_KEY,
  });

  const hasEnvAuth = envToken
    || envAuthType === 'mtls' || envMtls
    || envAuthType === 'cookie' || envCookie
    || envAuthType === 'oauth' || envOAuth;

  if (envDomain && hasEnvAuth) {
    const inferredAuthType = envAuthType
      || (envOAuth && !envToken ? 'oauth' : undefined)
      || (envMtls && !envToken ? 'mtls' : undefined)
      || (envCookie && !envToken ? 'cookie' : undefined);
    const authType = normalizeAuthType(inferredAuthType, Boolean(envEmail));
    let apiPath;

    try {
      apiPath = normalizeApiPath(envApiPath, envDomain);
    } catch (error) {
      console.error(chalk.red(`❌ ${error.message}`));
      process.exit(1);
    }

    const authErrors = validateAuthConfig(
      { authType, token: envToken, email: envEmail, cookie: envCookie, mtls: envMtls, oauth: envOAuth, protocol: envProtocol },
      'CONFLUENCE_AUTH_TYPE=mtls'
    );
    if (authErrors.length > 0) {
      console.error(chalk.red(`❌ ${authErrors.join(' ')}`));
      if (authType === 'basic' && !envEmail) {
        console.log(chalk.yellow('Set CONFLUENCE_EMAIL (or CONFLUENCE_USERNAME for on-premise) or switch to bearer auth by setting CONFLUENCE_AUTH_TYPE=bearer.'));
      }
      if (authType === 'mtls' && !envMtls) {
        console.log(chalk.yellow('Set CONFLUENCE_TLS_CLIENT_CERT and CONFLUENCE_TLS_CLIENT_KEY. Optionally set CONFLUENCE_TLS_CA_CERT.'));
      }
      if (authType === 'cookie' && !envCookie) {
        console.log(chalk.yellow('Set CONFLUENCE_COOKIE with your session cookie (e.g., "JSESSIONID=...").'));
      }
      if (authType === 'oauth' && !envOAuth?.cloudId) {
        console.log(chalk.yellow('Set CONFLUENCE_CLOUD_ID and CONFLUENCE_OAUTH_ACCESS_TOKEN or run "confluence oauth-login".'));
      }
      process.exit(1);
    }

    return {
      domain: envDomain.trim(),
      protocol: normalizeProtocol(envProtocol),
      apiPath,
      token: envToken ? envToken.trim() : undefined,
      email: envEmail ? envEmail.trim() : undefined,
      cookie: envCookie ? envCookie.trim() : undefined,
      authType,
      oauth: envOAuth,
      mtls: envMtls,
      readOnly: envReadOnly === 'true',
      forceCloud: envForceCloud === 'true',
      linkStyle: envLinkStyle
    };
  }

  // Resolve profile: explicit param > CONFLUENCE_PROFILE env var > activeProfile > default
  const resolvedProfileName = profileName
    || process.env.CONFLUENCE_PROFILE
    || null;

  const fileData = readConfigFile();

  if (!fileData) {
    console.error(chalk.red('❌ No configuration found!'));
    console.log(chalk.yellow('Please run "confluence init" to set up your configuration.'));
    console.log(chalk.gray('Or set environment variables: CONFLUENCE_DOMAIN, CONFLUENCE_API_TOKEN (or CONFLUENCE_PASSWORD), CONFLUENCE_EMAIL (or CONFLUENCE_USERNAME), and optionally CONFLUENCE_API_PATH, CONFLUENCE_PROTOCOL.'));
    process.exit(1);
  }

  const targetProfile = resolvedProfileName || fileData.activeProfile || DEFAULT_PROFILE;
  const storedConfig = fileData.profiles && fileData.profiles[targetProfile];

  if (!storedConfig) {
    console.error(chalk.red(`❌ Profile "${targetProfile}" not found!`));
    const available = fileData.profiles ? Object.keys(fileData.profiles) : [];
    if (available.length > 0) {
      console.log(chalk.yellow(`Available profiles: ${available.join(', ')}`));
    }
    console.log(chalk.yellow('Run "confluence init --profile <name>" to create it, or "confluence profile list" to see available profiles.'));
    process.exit(1);
  }

  try {
    const trimmedDomain = (storedConfig.domain || '').trim();
    const trimmedToken = trimOptional(storedConfig.token);
    const trimmedEmail = storedConfig.email ? storedConfig.email.trim() : undefined;
    const trimmedCookie = trimOptional(storedConfig.cookie);
    const authType = normalizeAuthType(storedConfig.authType, Boolean(trimmedEmail));
    const mtls = normalizeMtlsConfig(storedConfig.mtls);
    const oauth = normalizeOAuthConfig(storedConfig.oauth || storedConfig);
    let apiPath;

    if (!trimmedDomain) {
      console.error(chalk.red('❌ Configuration file is missing required values.'));
      console.log(chalk.yellow('Run "confluence init" to refresh your settings.'));
      process.exit(1);
    }

    const authErrors = validateAuthConfig(
      { authType, token: trimmedToken, email: trimmedEmail, cookie: trimmedCookie, mtls, oauth, protocol: storedConfig.protocol },
      'mTLS authentication'
    );
    if (authErrors.length > 0) {
      console.error(chalk.red(`❌ ${authErrors.join(' ')}`));
      console.log(chalk.yellow('Please rerun "confluence init" to refresh your settings.'));
      process.exit(1);
    }

    try {
      apiPath = normalizeApiPath(storedConfig.apiPath, trimmedDomain);
    } catch (error) {
      console.error(chalk.red(`❌ ${error.message}`));
      console.log(chalk.yellow('Please rerun "confluence init" to update your API path.'));
      process.exit(1);
    }

    const readOnly = envReadOnly !== undefined
      ? envReadOnly === 'true'
      : Boolean(storedConfig.readOnly);

    const forceCloud = envForceCloud !== undefined
      ? envForceCloud === 'true'
      : Boolean(storedConfig.forceCloud);

    const linkStyle = envLinkStyle
      ?? normalizeLinkStyle(storedConfig.linkStyle, `in profile "${targetProfile}"`);

    return {
      domain: trimmedDomain,
      protocol: normalizeProtocol(storedConfig.protocol),
      apiPath,
      token: trimmedToken,
      email: trimmedEmail,
      cookie: trimmedCookie,
      authType,
      oauth,
      mtls,
      readOnly,
      forceCloud,
      linkStyle,
      profileName: targetProfile
    };
  } catch (error) {
    console.error(chalk.red('❌ Error reading configuration file:'), error.message);
    console.log(chalk.yellow('Please run "confluence init" to recreate your configuration.'));
    process.exit(1);
  }
}

function listProfiles() {
  const fileData = readConfigFile();
  if (!fileData || !fileData.profiles || Object.keys(fileData.profiles).length === 0) {
    return { activeProfile: null, profiles: [] };
  }
  return {
    activeProfile: fileData.activeProfile,
    profiles: Object.keys(fileData.profiles).map(name => ({
      name,
      active: name === fileData.activeProfile,
      domain: fileData.profiles[name].domain,
      readOnly: Boolean(fileData.profiles[name].readOnly)
    }))
  };
}

function setActiveProfile(profileName) {
  const fileData = readConfigFile();
  if (!fileData) {
    throw new Error('No configuration file found. Run "confluence init" first.');
  }
  if (!fileData.profiles || !fileData.profiles[profileName]) {
    const available = fileData.profiles ? Object.keys(fileData.profiles) : [];
    throw new Error(`Profile "${profileName}" not found. Available: ${available.join(', ')}`);
  }
  fileData.activeProfile = profileName;
  saveConfigFile(fileData);
}

function deleteProfile(profileName) {
  const fileData = readConfigFile();
  if (!fileData) {
    throw new Error('No configuration file found. Run "confluence init" first.');
  }
  if (!fileData.profiles || !fileData.profiles[profileName]) {
    throw new Error(`Profile "${profileName}" not found.`);
  }
  if (Object.keys(fileData.profiles).length === 1) {
    throw new Error('Cannot delete the only remaining profile.');
  }
  delete fileData.profiles[profileName];
  if (fileData.activeProfile === profileName) {
    fileData.activeProfile = Object.keys(fileData.profiles)[0];
  }
  saveConfigFile(fileData);
}

module.exports = {
  initConfig,
  getConfig,
  saveOAuthConfig,
  updateOAuthTokens,
  clearOAuthTokens,
  listProfiles,
  setActiveProfile,
  deleteProfile,
  isValidProfileName,
  CONFIG_DIR,
  CONFIG_FILE,
  DEFAULT_PROFILE,
  normalizeOAuthConfig
};
