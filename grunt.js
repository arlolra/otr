module.exports = function (grunt) {

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
          '\n\n*/'
      }
    , concat: {
        dist: {
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
          , dest: 'otr.js'
        }
      }
    , min: {
        dist: {
            src: ['<banner:meta.banner>', 'otr.js']
          , dest: 'otr.min.js'
        }
      }

  })

  grunt.registerTask('default', 'concat min')

}