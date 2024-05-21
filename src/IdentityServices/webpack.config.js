const path = require('path');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
    entry: ['./app.js'],
    output: {
        filename: 'bundle.js',
        path: path.resolve(__dirname, 'wwwroot/js')
    },
    module: {
        rules: [
            {
                test: /\.css$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    'css-loader'
                ]
            },
            {
                test: /\.scss$/,
                use: [
                    MiniCssExtractPlugin.loader,
                    'css-loader',
                    'sass-loader'
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
        new MiniCssExtractPlugin({
            filename: '../css/bundle.css',
        }),
    ],
}