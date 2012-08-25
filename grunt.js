module.exports = function (grunt) {

  var cryptojs = [
      'vendor/cryptojs/core.js'
    , 'vendor/cryptojs/enc-base64.js'
    , 'vendor/cryptojs/cipher-core.js'
    , 'vendor/cryptojs/aes.js'
    , 'vendor/cryptojs/sha1.js'
    , 'vendor/cryptojs/sha256.js'
    , 'vendor/cryptojs/hmac.js'
    , 'vendor/cryptojs/pad-nopadding.js'
    , 'vendor/cryptojs/mode-ctr.js'
  ]

  grunt.loadNpmTasks('grunt-clean')

  grunt.initConfig({

      pkg: '<json:package.json>'
    , meta: {
        banner: 
          '/*!\n\n  <%= pkg.name %>.js v<%= pkg.version %> - ' +
          '<%= grunt.template.today("yyyy-mm-dd") %>\n' +
          '  (c) <%= grunt.template.today("yyyy") %> - <%= pkg.author %>\n' +
          '  Freely distributed under the <%= pkg.license %> license.\n\n' +
          '  This file is concatenated for the browser.\n' +
          '  Please see: <%= pkg.homepage %>' +
          '\n\n*/',
        cryptojs: 'module.exports = CryptoJS'
      }
    , concat: {
          otr: {
              src: [
                  '<banner:meta.banner>'
                , 'lib/dh.js'
                , 'lib/states.js'
                , 'lib/helpers.js'
                , 'lib/dsa.js'
                , 'lib/sm.js'
                , 'lib/ake.js'
                , 'lib/parse.js'
                , 'lib/otr.js'
              ]
            , dest: 'build/otr.js'
          }
        , cryptojs: {
              src: cryptojs.concat('<banner:meta.cryptojs>')
            , dest: 'vendor/crypto.js'
          }
        , crypto_dep: {
              src: cryptojs
            , dest: 'build/dep/crypto.js'
          }
      }
    , min: {
        otr: {
            src: ['<banner:meta.banner>', 'build/otr.js']
          , dest: 'build/otr.min.js'
        }
      }
    , clean: {
        folder: 'build/'
      }
  })

  grunt.registerTask('copy_dep', function () {
    var files = ['seedrandom.js', 'bigint.js']
      , src = 'vendor/'
      , dest = 'build/dep/'
    files.forEach(function (f) {
      grunt.file.copy(src + f, dest + f)
    })
  })

  grunt.registerTask('cryptojs', 'concat:cryptojs')
  grunt.registerTask('otr', 'concat:otr min:otr')
  grunt.registerTask('dep', 'concat:crypto_dep copy_dep')
  grunt.registerTask('default', 'clean otr dep')

}