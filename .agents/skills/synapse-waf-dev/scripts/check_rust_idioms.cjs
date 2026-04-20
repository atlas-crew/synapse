const fs = require('fs');
const path = require('path');

/**
 * Scan Rust source code for un-idiomatic patterns discouraged in this project.
 * Flags: .unwrap(), .expect(), panic!(), and unsafe blocks.
 */
const DISCOURAGED_PATTERNS = [
  { regex: /\.unwrap\(\)/, name: '.unwrap()', recommendation: 'Use .ok_or() or .map_err()' },
  { regex: /\.expect\(/, name: '.expect()', recommendation: 'Handle the error gracefully' },
  { regex: /panic!\(/, name: 'panic!()', recommendation: 'Return a Result' },
  { regex: /unsafe\s*{/, name: 'unsafe block', recommendation: 'Avoid unsafe code unless strictly necessary' }
];

function scanFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const issues = [];

  // Skip test files for .unwrap() checks as they are common there
  const isTestFile = filePath.includes('/tests/') || filePath.endsWith('_test.rs');

  lines.forEach((line, idx) => {
    DISCOURAGED_PATTERNS.forEach(pattern => {
      if (isTestFile && (pattern.name === '.unwrap()' || pattern.name === '.expect()')) return;
      
      if (pattern.regex.test(line)) {
        issues.push({
          file: path.relative(process.cwd(), filePath),
          line: idx + 1,
          pattern: pattern.name,
          recommendation: pattern.recommendation,
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
    console.log('Usage: node check_rust_idioms.cjs <dir_or_file>');
    process.exit(1);
  }

  let allIssues = [];
  const walk = (dir) => {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (stat.isDirectory() && file !== 'target') {
        walk(filePath);
      } else if (file.endsWith('.rs')) {
        allIssues = allIssues.concat(scanFile(filePath));
      }
    });
  };

  args.forEach(arg => {
    const stat = fs.statSync(arg);
    if (stat.isDirectory()) walk(arg);
    else if (arg.endsWith('.rs')) allIssues = allIssues.concat(scanFile(arg));
  });

  if (allIssues.length > 0) {
    console.log('🛡️ Edge Protection - Rust Idiom Audit');
    console.log('------------------------------------');
    allIssues.forEach(issue => {
      console.log(`\n📍 ${issue.file}:${issue.line} [${issue.pattern}]`);
      console.log(`   Context: ${issue.text}`);
      console.log(`   💡 Recommendation: ${issue.recommendation}`);
    });
    console.log(`\n❌ Found ${allIssues.length} discouraged patterns.`);
    process.exit(1);
  } else {
    console.log('✅ No discouraged Rust patterns found.');
  }
}

main();
