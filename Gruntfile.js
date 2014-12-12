module.exports = function (grunt) {

    grunt.initConfig({
        uglify: {
            default: {
                options: {
                    preserveComments: 'some',
                    sourceMap: 'fidem-signer.min.map',
                    sourceMappingURL: 'fidem-signer.min.map'
                },
                files: {
                    'fidem-signer.min.js': 'fidem-signer.js'
                }
            }
        },
        browserify: {
            main: {
                src: 'index.js',
                dest: 'fidem-signer.js',
                options: {
                    standalone: 'signer'
                }
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-uglify');
    grunt.loadNpmTasks('grunt-browserify');
    grunt.registerTask('default', ['browserify', 'uglify']);
};