# CakePHP JWT Authenticate plugin

[![Build Status](https://img.shields.io/travis/ADmad/cakephp-jwt-auth/master.svg?style=flat-square)](https://travis-ci.org/ADmad/cakephp-jwt-auth)
[![Coverage](https://img.shields.io/codecov/c/github/ADmad/cakephp-jwt-auth.svg?style=flat-square)](https://codecov.io/github/ADmad/cakephp-jwt-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/ADmad/cakephp-jwt-auth.svg?style=flat-square)](https://packagist.org/packages/ADmad/cakephp-jwt-auth)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE.txt)

Plugin containing AuthComponent's authenticate class for authenticating using
[JSON Web Tokens](http://jwt.io/). You can read about JSON Web Token
specification in detail [here](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-27).

## Installation

```sh
composer require admad/cakephp-jwt-auth
```

## Usage

In your app's `config/bootstrap.php` add:

```php
// In config/bootstrap.php
Plugin::load('ADmad/JwtAuth');
```

or using cake's console:

```sh
./bin/cake plugin load ADmad/JwtAuth
```

## Configuration:

Setup `AuthComponent`:

```php
    // In your controller, for e.g. src/Api/AppController.php
    public function initialize()
    {
        parent::initialize();

        $this->loadComponent('Auth', [
            'storage' => 'Memory',
            'authenticate' => [
                'ADmad/JwtAuth.Jwt' => [
                    'userModel' => 'Users',
                    'fields' => [
                        'username' => 'id'
                    ],

                    'parameter' => 'token',

                    // Boolean indicating whether the "sub" claim of JWT payload
                    // should be used to query the Users model and get user info.
                    // If set to `false` JWT's payload is directly returned.
                    'queryDatasource' => true,
                ]
            ],

            'unauthorizedRedirect' => false,
            'checkAuthIn' => 'Controller.initialize',

            // If you don't have a login action in your application set
            // 'loginAction' to false to prevent getting a MissingRouteException.
            'loginAction' => false
        ]);
    }
```

## Working

The authentication class checks for the token in two locations:

- `HTTP_AUTHORIZATION` environment variable:

  It first checks if token is passed using `Authorization` request header.
  The value should be of form `Bearer <token>`. The `Authorization` header name
  and token prefix `Bearer` can be customized using options `header` and `prefix`
  respectively.

- The query string variable specified using `parameter` config:

  Next it checks if the token is present in query string. The default variable
  name is `token` and can be customzied by using the `parameter` config shown
  above.

### Known Issue
  Some servers don't populate `$_SERVER['HTTP_AUTHORIZATION']` when
  `Authorization` header is set. So it's up to you to ensure that either
  `$_SERVER['HTTP_AUTHORIZATION']` or `$_ENV['HTTP_AUTHORIZATION']` is set.

  For e.g. for apache you could use the following:

  ```
  RewriteEngine On
  RewriteCond %{HTTP:Authorization} ^(.*)
  RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
  ```

## Token Generation

You can use `\Firebase\JWT\JWT::encode()` of the [firebase/php-jwt](https://github.com/firebase/php-jwt)
lib, which this plugin depends on, to generate tokens.

**The payload should have the "sub" (subject) claim whos value is used to query the
Users model and find record matching the "id" field.**

You can set the `queryDatasource` option to `false` to directly return the token's
payload as user info without querying datasource for matching user record.

## Further reading

For an end to end usage example check out [this](http://www.bravo-kernel.com/2015/04/how-to-add-jwt-authentication-to-a-cakephp-3-rest-api/) blog post by Bravo Kernel.
