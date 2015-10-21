# CakePHP JWT Authenticate plugin

[![Build Status](https://img.shields.io/travis/ADmad/cakephp-jwt-auth/master.svg?style=flat-square)](https://travis-ci.org/ADmad/cakephp-jwt-auth)
[![Coverage](https://img.shields.io/coveralls/ADmad/cakephp-jwt-auth/master.svg?style=flat-square)](https://coveralls.io/r/ADmad/cakephp-jwt-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/ADmad/cakephp-jwt-auth.svg?style=flat-square)](https://packagist.org/packages/ADmad/cakephp-jwt-auth)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE.txt)

Plugin containing AuthComponent's authenticate class for authenticating using
[JSON Web Tokens](http://jwt.io/). You can read about JSON Web Token
specification in detail [here](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-27).

## Requirements

* CakePHP 3.0+

## Installation

```sh
composer require admad/cakephp-jwt-auth:1.0.x-dev
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
            'authenticate', [
                'ADmad/JwtAuth.Jwt' => [
                    'parameter' => '_token',
                    'userModel' => 'Users',
                    'scope' => ['Users.active' => 1],
                    'fields' => [
                        'id' => 'id'
                    ]
                ]
            ],
            'unauthorizedRedirect' => false,
            // Config below is available since CakePHP 3.1.
            // It makes user info available in controller's beforeFilter() which is not possible in CakePHP 3.0.
            'checkAuthIn' => 'Controller.initialize',
        ]);
    }
```

## Working

The authentication class checks for the token in two locations:

- `HTTP_AUTHORIZATION` environment variable:

  It first checks if token is passed using `Authorization` request header.
  The value should be of form `Bearer <token>`.

- The query string variable specified using `parameter` config:

  Next it checks if the token is present in query string. The default variable
  name is `_token` and can be customzied by using the `parameter` config shown
  above.

The payload of the token should either have key `id` or `record`. If
`id` key exists it's value will be used to query against the primary key field
of users table.

If `record` key exists it's value will be returned as user record. No check
will be done against the database.

## Additional Info

For stateless authentication you need to set the `AuthComponent` "storage" value to be "Memory" otherwise `AuthComponent` will write to session.

`AuthComponent` performs it's authentication routine for stateless auth *after* your controller's `beforeFilter()` has run. So trying to get user info using `$this->Auth->user()` in `beforeFilter()` will always return `null`.

As of CakPHP 3.1 though you can set a new config option `checkAuthIn` to `Controller.initialize` which makes `AuthComponent` do the authentication routine before controller's `beforeFilter()` is called.


## Further reading

For an end to end usage example check out [this](http://www.bravo-kernel.com/2015/04/how-to-add-jwt-authentication-to-a-cakephp-3-rest-api/) blog post by Bravo Kernel.
