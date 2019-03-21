import pkg from './package.json'

let now = new Date();
let banner = `/*!
  ${pkg.name}.js v${pkg.version} - ${now.toDateString()}
  (c) ${now.getFullYear()} - ${pkg.author}
  Freely distributed under the ${pkg.license} license.

  This file is concatenated for the browser.
  Please see: ${pkg.homepage}
*/\n\n`;

export default [{
  input: 'index.js',
  external: ['crypto'],
  output: {
    file: 'build/otr.js',
    format: 'umd',
    name: 'arlolra',
    banner,
    globals: {
      crypto: 'crypto'
    }
  }
}, {
  input: 'lib/dsa-webworker.js',
  external: ['crypto'],
  output: {
    file: 'build/dsa-webworker.js',
    format: 'umd',
    banner,
    globals: {
      crypto: 'crypto'
    }
  }
}, {
  input: 'lib/sm-webworker.js',
  external: ['crypto'],
  output: {
    file: 'build/sm-webworker.js',
    format: 'umd',
    banner,
    globals: {
      crypto: 'crypto'
    }
  }
}]
