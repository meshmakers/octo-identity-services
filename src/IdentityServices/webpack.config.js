const path = require('path');
const autoprefixer = require('autoprefixer');

module.exports = {
    entry: ['./app.js', './app.scss', './wwwroot/css/site.css'],
    output: {
        filename: 'bundle.js',
        path: path.resolve(__dirname, 'wwwroot/js')
    },
    module: {
        rules: [
            {
                test: /\.css$/,
                use: [{loader: 'style-loader'}, {loader: 'css-loader'}]
            },
            {
                test: /\.scss$/,
                use: [
                    {
                        loader: 'file-loader',
                        options: {
                            name: 'bundle.css',
                        },
                    },
                    {loader: 'extract-loader'},
                    {loader: 'css-loader'},
                    {
                        loader: 'postcss-loader',
                        options: {
                            postcssOptions: {
                                plugins: [
                                    autoprefixer()
                                ]
                            }
                        }
                    },
                    {
                        loader: 'sass-loader',
                        options: {
                            // Prefer Dart Sass
                            implementation: require('sass'),

                            // See https://github.com/webpack-contrib/sass-loader/issues/804
                            webpackImporter: false,
                            sassOptions: {
                                includePaths: ['./node_modules'],
                            },
                        },
                    }
                ],
            },
            {
                test: /\.js$/,
                loader: 'babel-loader',
                options: {
                    presets: ['@babel/preset-env'],
                },
            }
        ]
    },
    plugins: [
        // new webpack.ProvidePlugin({
        //     $: 'jquery',
        //     jQuery: 'jquery'
        // }),
    ],
}