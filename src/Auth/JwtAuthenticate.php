<?php
declare(strict_types=1);

namespace ADmad\JwtAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Utility\Security;
use Exception;
use Firebase\JWT\JWT;

/**
 * An authentication adapter for authenticating using JSON Web Tokens.
 *
 * ```
 *  $this->Auth->config('authenticate', [
 *      'ADmad/JwtAuth.Jwt' => [
 *          'parameter' => 'token',
 *          'userModel' => 'Users',
 *          'fields' => [
 *              'username' => 'id'
 *          ],
 *      ]
 *  ]);
 * ```
 *
 * @copyright 2015-Present ADmad
 * @license MIT
 * @see http://jwt.io
 * @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
 */
class JwtAuthenticate extends BaseAuthenticate
{
    /**
     * Parsed token.
     *
     * @var string|null
     */
    protected $_token;

    /**
     * Payload data.
     *
     * @var object|null
     */
    protected $_payload;

    /**
     * Exception.
     *
     * @var \Throwable|null
     */
    protected $_error;

    /**
     * Constructor.
     *
     * Settings for this object.
     *
     * - `cookie` - Cookie name to check. Defaults to `false`.
     * - `header` - Header name to check. Defaults to `'authorization'`.
     * - `prefix` - Token prefix. Defaults to `'bearer'`.
     * - `parameter` - The url parameter name of the token. Defaults to `token`.
     *   First $_SERVER['HTTP_AUTHORIZATION'] is checked for token value.
     *   Its value should be of form "Bearer <token>". If empty this query string
     *   paramater is checked.
     * - `allowedAlgs` - List of supported verification algorithms.
     *   Defaults to ['HS256']. See API of JWT::decode() for more info.
     * - `queryDatasource` - Boolean indicating whether the `sub` claim of JWT
     *   token should be used to query the user model and get user record. If
     *   set to `false` JWT's payload is directly retured. Defaults to `true`.
     * - `userModel` - The model name of users, defaults to `Users`.
     * - `fields` - Key `username` denotes the identifier field for fetching user
     *   record. The `sub` claim of JWT must contain identifier value.
     *   Defaults to ['username' => 'id'].
     * - `finder` - Finder method.
     * - `unauthenticatedException` - Fully namespaced exception name. Exception to
     *   throw if authentication fails. Set to false to do nothing.
     *   Defaults to '\Cake\Http\Exception\UnauthorizedException'.
     * - `key` - The key, or map of keys used to decode JWT. If not set, value
     *   of Security::salt() will be used.
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry
     *   used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, array $config)
    {
        $defaultConfig = [
            'cookie' => false,
            'header' => 'authorization',
            'prefix' => 'bearer',
            'parameter' => 'token',
            'queryDatasource' => true,
            'fields' => ['username' => 'id'],
            'unauthenticatedException' => UnauthorizedException::class,
            'key' => null,
        ];

        $this->setConfig($defaultConfig);

        if (empty($config['allowedAlgs'])) {
            $config['allowedAlgs'] = ['HS256'];
        }

        parent::__construct($registry, $config);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Http\ServerRequest $request The request object.
     * @param \Cake\Http\Response $response Response object.
     * @return false|array User record array or false on failure.
     */
    public function authenticate(ServerRequest $request, Response $response)
    {
        return $this->getUser($request);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Http\ServerRequest $request Request object.
     * @return false|array User record array or false on failure.
     */
    public function getUser(ServerRequest $request)
    {
        $payload = $this->getPayload($request);

        if (empty($payload)) {
            return false;
        }

        if (!$this->_config['queryDatasource']) {
            return json_decode(json_encode($payload), true);
        }

        if (!isset($payload->sub)) {
            return false;
        }

        $user = $this->_findUser((string)$payload->sub);
        if (!$user) {
            return false;
        }

        unset($user[$this->_config['fields']['password']]);

        return $user;
    }

    /**
     * Get payload data.
     *
     * @param \Cake\Http\ServerRequest|null $request Request instance or null
     * @return object|null Payload object on success, null on failurec
     */
    public function getPayload(?ServerRequest $request = null)
    {
        if (!$request) {
            return $this->_payload;
        }

        $payload = null;

        $token = $this->getToken($request);
        if ($token) {
            $payload = $this->_decode($token);
        }

        return $this->_payload = $payload;
    }

    /**
     * Get token from header or query string.
     *
     * @param \Cake\Http\ServerRequest|null $request Request object.
     * @return string|null Token string if found else null.
     */
    public function getToken(?ServerRequest $request = null)
    {
        $config = $this->_config;

        if ($request === null) {
            return $this->_token;
        }

        $header = $request->getHeaderLine($config['header']);
        if ($header && stripos($header, $config['prefix']) === 0) {
            return $this->_token = str_ireplace($config['prefix'] . ' ', '', $header);
        }

        if (!empty($this->_config['cookie'])) {
            $token = $request->getCookie($this->_config['cookie']);
            if ($token !== null) {
                /** @psalm-suppress PossiblyInvalidCast */
                $token = (string)$token;
            }

            return $this->_token = $token;
        }

        if (!empty($this->_config['parameter'])) {
            $token = $request->getQuery($this->_config['parameter']);
            if ($token !== null) {
                /** @psalm-suppress PossiblyInvalidCast */
                $token = (string)$token;
            }

            return $this->_token = $token;
        }

        return $this->_token;
    }

    /**
     * Decode JWT token.
     *
     * @param string $token JWT token to decode.
     * @return object|null The JWT's payload as a PHP object, null on failure.
     */
    protected function _decode(string $token)
    {
        $config = $this->_config;
        try {
            $payload = JWT::decode(
                $token,
                $config['key'] ?: Security::getSalt(),
                $config['allowedAlgs']
            );

            return $payload;
        } catch (Exception $e) {
            if (Configure::read('debug')) {
                throw $e;
            }
            $this->_error = $e;
        }

        return null;
    }

    /**
     * Handles an unauthenticated access attempt. Depending on value of config
     * `unauthenticatedException` either throws the specified exception or returns
     * null.
     *
     * @param \Cake\Http\ServerRequest $request A request object.
     * @param \Cake\Http\Response $response A response object.
     * @throws \Cake\Http\Exception\UnauthorizedException Or any other
     *   configured exception.
     * @return void
     */
    public function unauthenticated(ServerRequest $request, Response $response)
    {
        if (!$this->_config['unauthenticatedException']) {
            return;
        }

        $message = $this->_error
            ? $this->_error->getMessage()
            : $this->_registry->get('Auth')->getConfig('authError');

        /** @var \Throwable $exception */
        $exception = new $this->_config['unauthenticatedException']($message);
        throw $exception;
    }
}
