export default {
  input: 'index.js',
  external: ['crypto'],
  output: {
    file: 'bundle.js',
    format: 'umd',
    name: 'arlolra',
    globals: {
      crypto: 'crypto'
    }
  }
}
