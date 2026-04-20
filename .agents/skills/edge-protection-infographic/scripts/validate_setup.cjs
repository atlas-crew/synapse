const { execSync } = require('child_process');

/**
 * Validate system dependencies for the Edge Protection infographic pipeline.
 * Checks for ImageMagick (magick) and Google Chrome.
 */
function checkDependency(command, name) {
  try {
    execSync(command, { stdio: 'ignore' });
    console.log(`✅ ${name} found.`);
    return true;
  } catch (e) {
    console.error(`❌ ${name} NOT found.`);
    return false;
  }
}

function main() {
  console.log('🛡️ Edge Protection - Infographic Setup Check');
  console.log('-------------------------------------------');

  const magick = checkDependency('magick -version', 'ImageMagick (magick)');
  
  // Try common chrome binary names
  let chrome = false;
  const chromePaths = [
    '/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome',
    'google-chrome',
    'chromium'
  ];

  for (const path of chromePaths) {
    try {
      execSync(`${path} --version`, { stdio: 'ignore' });
      console.log(`✅ Google Chrome found at: ${path.replace(/\\/g, '')}`);
      chrome = true;
      break;
    } catch (e) {}
  }

  if (!chrome) {
    console.error('❌ Google Chrome NOT found in standard locations.');
  }

  if (magick && chrome) {
    console.log('\n✨ Setup is ready for infographic rendering.');
  } else {
    console.log('\n⚠️  Please install missing dependencies before rendering.');
    process.exit(1);
  }
}

main();
