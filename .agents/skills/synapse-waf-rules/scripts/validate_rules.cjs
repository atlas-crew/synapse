const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

/**
 * Validate Synapse WAF rules against the project's Rust schema.
 * Checks for required fields, numeric IDs, and valid match kinds.
 */
function validateRule(rule, filePath) {
  const errors = [];
  const prefix = `[${path.basename(filePath)}: ID ${rule.id || 'unknown'}]`;

  if (!rule.id || typeof rule.id !== 'number') {
    errors.push(`${prefix} Missing or non-numeric ID`);
  }

  if (!rule.description || typeof rule.description !== 'string') {
    errors.push(`${prefix} Missing or non-string description`);
  }

  if (!Array.isArray(rule.matches) || rule.matches.length === 0) {
    errors.push(`${prefix} Rules must have at least one match condition`);
  } else {
    rule.matches.forEach((condition, idx) => {
      if (!condition.type) {
        errors.push(`${prefix} Match condition #${idx} is missing 'type'`);
      }
      // Basic check for common match types (extensible)
      const validTypes = ['uri', 'method', 'header', 'args', 'named_argument', 'request_json', 'boolean', 'to_lowercase', 'percent_decode', 'decode_if_base64', 'sql_analyzer', 'xss_analyzer', 'cmd_analyzer', 'path_traversal_analyzer', 'ja4', 'ja4h', 'dlp_violation', 'schema_violation'];
      if (condition.type && !validTypes.includes(condition.type)) {
        errors.push(`${prefix} Match condition #${idx} has unknown type: '${condition.type}'`);
      }
    });
  }

  return errors;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: node validate_rules.cjs <rule_file.json|yaml>');
    process.exit(1);
  }

  let hasErrors = false;
  args.forEach(filePath => {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const data = filePath.endsWith('.json') ? JSON.parse(content) : yaml.load(content);
      
      const rules = Array.isArray(data) ? data : [data];
      rules.forEach(rule => {
        const errors = validateRule(rule, filePath);
        if (errors.length > 0) {
          errors.forEach(err => console.error(err));
          hasErrors = true;
        }
      });
    } catch (e) {
      console.error(`Error reading/parsing ${filePath}: ${e.message}`);
      hasErrors = true;
    }
  });

  if (!hasErrors) {
    console.log('✅ All rules validated successfully.');
  } else {
    process.exit(1);
  }
}

main();
