import { describe, it, expect } from 'vitest';
import { convertSigmaToSql } from '../sigmaToSql';

describe('convertSigmaToSql', () => {
  it('converts a simple Sigma rule to SQL', () => {
    const sigma = `
title: Suspicious User Agent
logsource:
  product: webserver
detection:
  selection:
    useragent: 'curl/*'
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain('SELECT * FROM signal_events');
    expect(sql).toContain("JSONExtractString(metadata, 'user_agent') ILIKE 'curl/%'");
  });

  it('handles field mapping for IP addresses', () => {
    const sigma = `
detection:
  selection:
    src_ip: '192.168.1.1'
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("source_ip = toIPv4('192.168.1.1')");
  });

  it('handles multiple values in selection (OR logic)', () => {
    const sigma = `
detection:
  selection:
    status: [404, 500]
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("JSONExtractString(metadata, 'status_code') IN ('404', '500')");
  });

  it('handles multiple fields in selection (AND logic)', () => {
    const sigma = `
detection:
  selection:
    method: POST
    status: 200
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("JSONExtractString(metadata, 'method') = 'POST'");
    expect(sql).toContain("JSONExtractString(metadata, 'status_code') = '200'");
    expect(sql).toContain(' AND ');
  });

  it('prevents SQL injection by escaping single quotes', () => {
    const sigma = `
detection:
  selection:
    useragent: "') OR 1=1;--"
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("= ''') OR 1=1;--')");
  });

  it('includes default boilerplate like ORDER BY and LIMIT', () => {
    const sigma = `
detection:
  selection:
    method: GET
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain('ORDER BY timestamp DESC');
    expect(sql).toContain('LIMIT 1000');
  });

  it('handles "1 of them" condition', () => {
    const sigma = `
detection:
  sel1:
    method: POST
  sel2:
    status: 404
  condition: 1 of them
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("JSONExtractString(metadata, 'method') = 'POST'");
    expect(sql).toContain(' OR ');
    expect(sql).toContain("JSONExtractString(metadata, 'status_code') = '404'");
  });

  it('handles "all of them" condition', () => {
    const sigma = `
detection:
  sel1:
    method: POST
  sel2:
    status: 404
  condition: all of them
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("JSONExtractString(metadata, 'method') = 'POST'");
    expect(sql).toContain(' AND ');
    expect(sql).toContain("JSONExtractString(metadata, 'status_code') = '404'");
  });

  it('handles complex logical conditions with NOT and parentheses', () => {
    const sigma = `
detection:
  sel1:
    method: POST
  sel2:
    status: 404
  condition: sel1 and not sel2
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("(JSONExtractString(metadata, 'method') = 'POST') and not (JSONExtractString(metadata, 'status_code') = '404')");
  });

  it('handles keyword search (no field specified)', () => {
    const sigma = `
detection:
  selection:
    - 'mimikatz'
    - 'cobaltstrike'
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("metadata ILIKE '%mimikatz%' OR signal_type ILIKE '%mimikatz%'");
    expect(sql).toContain("metadata ILIKE '%cobaltstrike%' OR signal_type ILIKE '%cobaltstrike%'");
    expect(sql).toContain(' OR ');
  });

  it('handles nested selection structures (OR of ANDs)', () => {
    const sigma = `
detection:
  selection:
    - method: POST
      path: '/login'
    - method: GET
      path: '/admin'
  condition: selection
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain("(JSONExtractString(metadata, 'method') = 'POST' AND JSONExtractString(metadata, 'path') = '/login')");
    expect(sql).toContain("(JSONExtractString(metadata, 'method') = 'GET' AND JSONExtractString(metadata, 'path') = '/admin')");
    expect(sql).toContain(' OR ');
  });

  it('returns error comment on invalid YAML', () => {
    const sql = convertSigmaToSql('invalid: : yaml');
    expect(sql).toContain('-- Error parsing Sigma rule');
  });

  it('returns error comment on missing detection', () => {
    const sigma = `
title: Incomplete Rule
`;
    const sql = convertSigmaToSql(sigma);
    expect(sql).toContain('-- Error parsing Sigma rule: Missing detection section');
  });
});
