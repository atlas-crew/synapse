import yaml from 'js-yaml';

interface SigmaRule {
  title?: string;
  description?: string;
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: Record<string, any>;
}

/**
 * Converts a Sigma Rule (YAML string) to a ClickHouse SQL WHERE clause
 * tailor-made for the Signal Horizon 'signal_events' table.
 */
export function convertSigmaToSql(sigmaYaml: string): string {
  try {
    const rule = yaml.load(sigmaYaml) as SigmaRule;
    
    if (!rule || !rule.detection) {
      throw new Error('Missing detection section');
    }

    const { condition, ...selections } = rule.detection;

    if (!condition) {
      throw new Error('Missing condition');
    }

    // 1. Parse Selections into SQL fragments
    const selectionMap = new Map<string, string>();

    for (const [key, value] of Object.entries(selections)) {
      selectionMap.set(key, parseSelection(value));
    }

    // 2. Parse Condition logic (and, or, not, parens)
    let sqlCondition = parseCondition(condition, selectionMap);

    // 3. Construct full Query
    const comment = rule.title ? `-- ${rule.title}\n` : '';
    const description = rule.description ? `-- ${rule.description.replace(/\n/g, ' ')}\n` : '';

    return `${comment}${description}SELECT * FROM signal_events\nWHERE ${sqlCondition}\nORDER BY timestamp DESC LIMIT 1000`;

  } catch (err) {
    return `-- Error parsing Sigma rule: ${err instanceof Error ? err.message : String(err)}`;
  }
}

/**
 * Parses a single selection (e.g., 'selection_1') into a SQL fragment
 */
function parseSelection(selection: any): string {
  if (Array.isArray(selection)) {
    // List of items
    const parts = selection.map(item => {
      if (typeof item === 'string') return `(metadata ILIKE '%${escapeSql(item)}%' OR signal_type ILIKE '%${escapeSql(item)}%')`;
      return parseMap(item);
    });
    return `(${parts.join(' OR ')})`;
  } else if (typeof selection === 'object' && selection !== null) {
    // Single map -> AND logic
    return parseMap(selection);
  } else {
    // Keyword search (raw string) -> check metadata or common fields
    return `(metadata ILIKE '%${escapeSql(String(selection))}%' OR signal_type ILIKE '%${escapeSql(String(selection))}%')`;
  }
}

/**
 * Parses a map of field:value pairs into SQL (AND logic)
 */
function parseMap(map: Record<string, any>): string {
  const parts = [];
  for (const [field, value] of Object.entries(map)) {
    const col = mapFieldToColumn(field);
    
    if (Array.isArray(value)) {
      // field: [val1, val2] -> IN or OR
      if (value.some(v => typeof v === 'string' && v.includes('*'))) {
         // Wildcards present -> OR LIKE
         const likes = value.map(v => {
          const pattern = escapeSql(String(v)).replace(/\*/g, '%');
          if (col === 'source_ip') return `IPv4NumToString(source_ip) ILIKE '${pattern}'`;
          return `${col} ILIKE '${pattern}'`;
         });
         parts.push(`(${likes.join(' OR ')})`);
      } else {
        // Exact match list -> IN
        if (col === 'source_ip') {
          const values = value.map(v => `toIPv4('${escapeSql(String(v))}')`).join(', ');
          parts.push(`source_ip IN (${values})`);
        } else {
          const values = value.map(v => `'${escapeSql(String(v))}'`).join(', ');
          parts.push(`${col} IN (${values})`);
        }
      }
    } else {
      // Single value
      const strVal = String(value);
      if (strVal.includes('*')) {
        const pattern = escapeSql(strVal).replace(/\*/g, '%');
        if (col === 'source_ip') {
          parts.push(`IPv4NumToString(source_ip) ILIKE '${pattern}'`);
        } else {
          parts.push(`${col} ILIKE '${pattern}'`);
        }
      } else {
        if (col === 'source_ip') {
          parts.push(`source_ip = toIPv4('${escapeSql(strVal)}')`);
        } else {
          parts.push(`${col} = '${escapeSql(strVal)}'`);
        }
      }
    }
  }
  return `(${parts.join(' AND ')})`;
}

/**
 * Maps Sigma fields to Signal Horizon database columns
 */
function mapFieldToColumn(field: string): string {
  const lower = field.toLowerCase();
  
  // Direct mappings
  if (lower === 'c-ip' || lower === 'sourceip' || lower === 'src_ip') return 'source_ip';
  if (lower === 'cs-method' || lower === 'method') return "JSONExtractString(metadata, 'method')";
  if (lower === 'cs-uri-stem' || lower === 'url' || lower === 'uri') return "JSONExtractString(metadata, 'path')";
  if (lower === 'sc-status' || lower === 'status') return "JSONExtractString(metadata, 'status_code')";
  if (lower === 'useragent' || lower === 'user_agent') return "JSONExtractString(metadata, 'user_agent')";
  
  // Default: Try to extract from metadata JSON
  return `JSONExtractString(metadata, '${field}')`;
}

/**
 * Parses the condition string (e.g., "selection1 and not selection2")
 */
function parseCondition(condition: string | string[], map: Map<string, string>): string {
  if (Array.isArray(condition)) {
     // List of conditions implies OR (usually)
     return condition.map(c => parseCondition(c, map)).join(' OR ');
  }

  let sql = condition.toLowerCase();

  // 1. Replace keywords with placeholders to avoid collision
  // (Quick & dirty parser - adequate for 90% of rules)
  sql = sql
    .replace(/\b1 of them\b/g, 'or_all') // "1 of them" -> OR logic combined later
    .replace(/\ball of them\b/g, 'and_all'); // "all of them" -> AND logic

  // 2. Replace selection names with their SQL
  // Sort keys by length desc to avoid partial replacement (e.g. replacing 'sel' in 'selection')
  const keys = Array.from(map.keys()).sort((a, b) => b.length - a.length);
  
  for (const key of keys) {
    const val = map.get(key);
    // Use word boundaries, case-insensitive to match rule condition
    const regex = new RegExp(`\\b${key}\\b`, 'gi');
    if (val) {
        sql = sql.replace(regex, val);
    }
  }

  // 3. Handle special "X of them" keywords
  if (sql.includes('or_all')) {
    const allParts = Array.from(map.values());
    sql = sql.replace(/or_all/g, `(${allParts.join(' OR ')})`);
  }
  if (sql.includes('and_all')) {
    const allParts = Array.from(map.values());
    sql = sql.replace(/and_all/g, `(${allParts.join(' AND ')})`);
  }

  return sql;
}

function escapeSql(str: string): string {
  return str.replace(/'/g, "''");
}
