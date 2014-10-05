# CakePHP JWT Authenticate plugin

[![Build Status](https://travis-ci.org/ADmad/cakephp-jwt-auth.png?branch=master)](https://travis-ci.org/ADmad/cakephp-jwt-auth)

Plugin containing AuthComponent's authenticate class for authenticating using
[JSON Web Tokens](http://jwt.io/). You can read about it's specification in
detail [here](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-27).

## Requirements

* CakePHP 3.0+

## Installation

_[Composer]_

run: `composer require admad/cakephp-jwt-auth:1.0.x-dev`.

## Usage

In your app's `config/bootstrap.php` add: `CakePlugin::load('ADmad/JwtAuth')`;

## Configuration:

Setup the authentication class settings:

```php
    //in $components
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

    //Or in beforeFilter()
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
