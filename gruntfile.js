module.exports = function (grunt) {
  "use strict";

  var cryptojs = [
      'vendor/cryptojs/header.js'
    , 'vendor/cryptojs/core.js'
    , 'vendor/cryptojs/enc-base64.js'
    , 'vendor/cryptojs/cipher-core.js'
    , 'vendor/cryptojs/aes.js'
    , 'vendor/cryptojs/sha1.js'
    , 'vendor/cryptojs/sha256.js'
    , 'vendor/cryptojs/hmac.js'
    , 'vendor/cryptojs/pad-nopadding.js'
    , 'vendor/cryptojs/mode-ctr.js'
    , 'vendor/cryptojs/footer.js'
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
      }
    , concat: {
          otr: {
              options: {
                banner: '<%= meta.banner %>'
              }
            , src: [
                  'etc/header.js'
                , 'lib/const.js'
                , 'lib/helpers.js'
                , 'lib/dsa.js'
                , 'lib/parse.js'
                , 'lib/ake.js'
                , 'lib/sm.js'
                , 'lib/otr.js'
                , 'etc/footer.js'
              ]
            , dest: 'build/otr.js'
          }
        , cryptojs: {
              src: cryptojs
            , dest: 'vendor/crypto.js'
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
            jshintrc: '.jshintrc'
          }
        , all: ['*.js', 'lib/*.js', 'test/spec/unit/*.js']
      }
  })

  grunt.registerTask('copy_dep', function () {
    var files = ['salsa20.js', 'bigint.js', 'eventemitter.js', 'crypto.js']
      , src = 'vendor/'
      , dest = 'build/dep/'
    files.forEach(function (f) {
      grunt.file.copy(src + f, dest + f)
    })
  })

  grunt.registerTask('copy_ww', function () {
    var files = ['dsa-webworker.js', 'sm-webworker.js']
      , src = 'lib/'
      , dest = 'build/'
    files.forEach(function (f) {
      grunt.file.copy(src + f, dest + f)
    })
  })

  grunt.registerTask('otr', ['concat:otr', 'uglify:otr'])
  grunt.registerTask('dep', ['concat:cryptojs', 'copy_dep'])
  grunt.registerTask('ww', ['copy_ww'])
  grunt.registerTask('default', ['clean', 'otr', 'dep', 'ww'])

}