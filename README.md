# CakePHP JWT Authenticate plugin

[![Build Status](https://travis-ci.org/ADmad/cakephp-jwt-auth.png?branch=master)](https://travis-ci.org/ADmad/cakephp-jwt-auth)

Plugin containing AuthComponent's authenticate class for authenticating using
[JSON Web Tokens](http://jwt.io/). You can read about JSON Web Token
specification in detail [here](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-27).

## Requirements

* CakePHP 3.0+

## Installation

_[Composer]_

run: `composer require admad/cakephp-jwt-auth:1.0.x-dev`.

## Usage

In your app's `config/bootstrap.php` add:

```php
// In config/bootstrap.php
CakePlugin::load('ADmad/JwtAuth');
```

## Configuration:

Setup the authentication class settings:

```php
    // In AppController::$components
    public $components = [
        'Auth' => [
            'authenticate' => [
                'ADmad/JwtAuth.Jwt' => [
                    'parameter' => '_token',
                    'userModel' => 'Users',
                    'scope' => ['Users.active' => 1],
                    'fields' => [
                        'id' => 'id'
                    ]
                ]
            ]
        ]
    ];

    // Or in AppController::beforeFilter()
    $this->Auth->config('authenticate', [
        'ADmad/JwtAuth.Jwt' => [
            'parameter' => '_token',
            'userModel' => 'Users',
            'scope' => ['Users.active' => 1],
            'fields' => [
                'id' => 'id'
            ]
        ]
    ]);
```

## Working:

The authentication class checks for the token in two locations:

- `HTTP_AUTHORIZATION` environment variable:

  It first checks if token is passed using `Authorization` request header. 
  The value should be of form `Bearer <token>`.
  
- The query string variable specified using `parameter` config:

  Next it checks if the token is present in query string. The default variable
  name is `_token` and can be customzied by using the `parameter` config shown
  above.
