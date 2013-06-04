module.exports = function (grunt) {
  "use strict";

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

  grunt.loadNpmTasks('grunt-contrib-clean')
  grunt.loadNpmTasks('grunt-contrib-concat')
  grunt.loadNpmTasks('grunt-contrib-jshint')
  grunt.loadNpmTasks('grunt-contrib-uglify')

  grunt.initConfig({

      pkg: grunt.file.readJSON('package.json')
    , meta: {
          banner: 
            '/*!\n\n  <%= pkg.name %>.js v<%= pkg.version %> - ' +
            '<%= grunt.template.today("yyyy-mm-dd") %>\n' +
            '  (c) <%= grunt.template.today("yyyy") %> - <%= pkg.author %>\n' +
            '  Freely distributed under the <%= pkg.license %> license.\n\n' +
            '  This file is concatenated for the browser.\n' +
            '  Please see: <%= pkg.homepage %>' +
            '\n\n*/\n\n'
        , cryptojs: 'module.exports = CryptoJS'
        , globals: 'var OTR = {}, DSA = {}\n\n'
      }
    , concat: {
          otr: {
              options: {
                banner: '<%= meta.banner %><%= meta.globals %>'
              }
            , src: [
                  'lib/const.js'
                , 'lib/helpers.js'
                , 'lib/dsa.js'
                , 'lib/parse.js'
                , 'lib/ake.js'
                , 'lib/sm.js'
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
    , uglify: {
        otr: {
          options: {
              banner: '<%= meta.banner %>'
            , mangle: false
          },
          files: {
              'build/otr.min.js': ['build/otr.js']
          }
        }
      }
    , clean: {
        folder: 'build/'
      }
    , jshint: {
          options: {
              "-W015"    : true
            , "-W018"    : true
            , "browser"  : true
            , "devel"    : true
            , "node"     : true
            , "bitwise"  : false
            , "indent"   : 2
            , "laxcomma" : true
            , "asi"      : true
            , "undef"    : true
            , "strict"   : true
            , "expr"     : true
            , "white"    : false
            , "multistr" : true
            , "globals"  : {
                  "it"         : true
                , "beforeEach" : true
                , "before"     : true
                , "describe"   : true
              }
          }
        , all: ['*.js', 'lib/*.js', 'test/spec/unit/*.js']
    }
  })

  grunt.registerTask('copy_dep', function () {
    var files = ['salsa20.js', 'bigint.js', 'eventemitter.js']
      , src = 'vendor/'
      , dest = 'build/dep/'
    files.forEach(function (f) {
      grunt.file.copy(src + f, dest + f)
    })
  })

  grunt.registerTask('cryptojs', ['concat:cryptojs'])
  grunt.registerTask('otr', ['concat:otr', 'uglify:otr'])
  grunt.registerTask('dep', ['concat:crypto_dep', 'copy_dep'])
  grunt.registerTask('default', ['clean', 'otr', 'dep'])

}