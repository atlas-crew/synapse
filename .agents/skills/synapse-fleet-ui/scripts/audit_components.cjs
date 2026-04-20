const fs = require('fs');
const path = require('path');

/**
 * Scan React source code for Edge Protection UI standard violations.
 * Flags: Relative imports to tokens, hardcoded hex colors, and non-zero borderRadius.
 */
const VIOLATIONS = [
  { regex: /from\s+['"]\.\.\/tokens['"]/g, name: 'Relative Token Import', recommendation: "Import from '@/ui' instead" },
  { regex: /borderRadius:\s*[1-9]\d*px/g, name: 'Non-Zero Border Radius', recommendation: 'ALWAYS use borderRadius: 0' },
  { regex: /#[0-9a-fA-F]{3,6}(?!.*@\/ui)/g, name: 'Hardcoded Hex Color', recommendation: "Use 'colors' token from '@/ui'" }
];

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const issues = [];

  lines.forEach((line, idx) => {
    VIOLATIONS.forEach(violation => {
      if (violation.regex.test(line)) {
        issues.push({
          file: path.relative(process.cwd(), filePath),
          line: idx + 1,
          name: violation.name,
          recommendation: violation.recommendation,
          text: line.trim()
        });
      }
    });
  });

  return issues;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: node audit_components.cjs <dir_or_file>');
    process.exit(1);
  }

  let allIssues = [];
  const walk = (dir) => {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (stat.isDirectory() && file !== 'node_modules') {
        walk(filePath);
      } else if (file.endsWith('.tsx') || file.endsWith('.ts')) {
        allIssues = allIssues.concat(scanFile(filePath));
      }
    });
  };

  args.forEach(arg => {
    const stat = fs.statSync(arg);
    if (stat.isDirectory()) walk(arg);
    else if (arg.endsWith('.tsx') || arg.endsWith('.ts')) allIssues = allIssues.concat(scanFile(arg));
  });

  if (allIssues.length > 0) {
    console.log('🛡️ Edge Protection - UI Standard Audit');
    console.log('------------------------------------');
    allIssues.forEach(issue => {
      console.log(`\n📍 ${issue.file}:${issue.line} [${issue.name}]`);
      console.log(`   Context: ${issue.text}`);
      console.log(`   💡 Recommendation: ${issue.recommendation}`);
    });
    console.log(`\n❌ Found ${allIssues.length} UI standard violations.`);
    process.exit(1);
  } else {
    console.log('✅ No UI standard violations found.');
  }
}

main();
