const { DEFAULT_OAUTH_SCOPES, parseScopes } = require('../lib/oauth');

describe('OAuth scopes', () => {
  test('default OAuth scopes cover the full CLI command surface', () => {
    expect(DEFAULT_OAUTH_SCOPES).toEqual(expect.arrayContaining([
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
      'offline_access'
    ]));
  });

  test('parseScopes defaults to the shared OAuth scope list', () => {
    expect(parseScopes()).toEqual(DEFAULT_OAUTH_SCOPES);
  });

  test('parseScopes still allows explicit custom scopes', () => {
    expect(parseScopes('read:page:confluence,write:page:confluence offline_access')).toEqual([
      'read:page:confluence',
      'write:page:confluence',
      'offline_access'
    ]);
  });
});
