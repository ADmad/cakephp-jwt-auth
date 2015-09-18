<?php
namespace ADmad\JwtAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\Utility\Security;
use Exception;
use Firebase\JWT\JWT;

/**
 * An authentication adapter for authenticating using JSON Web Tokens.
 *
 * ```
 *  $this->Auth->config('authenticate', [
 *      'ADmad/JwtAuth.Jwt' => [
 *          'parameter' => '_token',
 *          'userModel' => 'Users',
 *          'scope' => ['User.active' => 1]
 *          'fields' => [
 *              'id' => 'id'
 *          ],
 *      ]
 *  ]);
 * ```
 *
 * @copyright 2014 A. Sarela aka ADmad
 * @license MIT
 * @see http://jwt.io
 * @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
 */
class JwtAuthenticate extends BaseAuthenticate
{

    /**
     * Parsed token
     *
     * @var string|null
     */
    protected $_token;

    /**
     * Payload data
     *
     * @var object|null
     */
    protected $_payload;

    /**
     * Exception
     *
     * @var \Exception
     */
    protected $_error;

    /**
     * Constructor.
     *
     * Settings for this object.
     *
     * - `parameter` - The url parameter name of the token. Defaults to `_token`.
     *   First $_SERVER['HTTP_AUTHORIZATION'] is checked for token value.
     *   Its value should be of form "Bearer <token>". If empty this query string
     *   paramater is checked.
     * - `userModel` - The model name of the User, defaults to `Users`.
     * - `fields` - Has key `id` whose value contains primary key field name.
     *   Defaults to ['id' => 'id'].
     * - `scope` - Additional conditions to use when looking up and authenticating
     *   users, i.e. `['Users.is_active' => 1].`
     * - `contain` - Extra models to contain.
     * - `unauthenticatedException` - Fully namespaced exception name. Exception to
     *   throw if authentication fails. Set to false to do nothing.
     *   Defaults to '\Cake\Network\Exception\UnauthorizedException'.
     * - `allowedAlgs` - List of supported verification algorithms.
     *   Defaults to ['HS256']. See API of JWT::decode() for more info.
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry
     *   used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, $config)
    {
        $this->config([
            'parameter' => '_token',
            'fields' => ['username' => 'id'],
            'unauthenticatedException' => '\Cake\Network\Exception\UnauthorizedException',
            'allowedAlgs' => ['HS256']
        ]);

        parent::__construct($registry, $config);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Network\Request $request The request object.
     * @param \Cake\Network\Response $response Response object.
     * @return bool|array User record array or false on failure.
     */
    public function authenticate(Request $request, Response $response)
    {
        return $this->getUser($request);
    }

    /**
     * Get user record based on info available in JWT.
     *
     * @param \Cake\Network\Request $request Request object.
     * @return bool|array User record array or false on failure.
     */
    public function getUser(Request $request)
    {
        $payload = $this->payload($request);

        // Token has full user record.
        if (isset($payload->record)) {
            // Trick to convert object of stdClass to array. Typecasting to
            // array doesn't convert property values which are themselves objects.
            return json_decode(json_encode($payload->record), true);
        }

        if (!isset($payload->sub)) {
            return false;
        }

        $user = $this->_findUser($payload->sub);
        if (!$user) {
            return false;
        }

        unset($user[$this->_config['fields']['password']]);
        return $user;
    }

    /**
     * Get payload data
     *
     * @param \Cake\Network\Request|null $request Request instance or null
     * @return object|null Payload object on success, null on failurec
     */
    public function payload($request = null)
    {
        if (!$request) {
            return $this->_payload;
        }

        $payload = null;

        $token = $this->token($request);
        if ($token) {
            $payload = $this->_decode($token);
        }

        return $this->_payload = $payload;
    }

    /**
     * Get token from header or query string.
     *
     * @param \Cake\Network\Request $request Request object.
     * @return string|null Token string if found else null.
     */
    public function token($request = null)
    {
        if ($request) {
            $token = $request->env('HTTP_AUTHORIZATION');

            // @codeCoverageIgnoreStart
            if (!$token && function_exists('getallheaders')) {
                $headers = array_change_key_case(getallheaders());
                if (isset($headers['authorization']) &&
                    substr($headers['authorization'], 0, 7) === 'Bearer '
                ) {
                    $token = $headers['authorization'];
                }
            }
            // @codeCoverageIgnoreEnd

            if ($token) {
                return substr($token, 7);
            }

            if (!empty($this->_config['parameter'])) {
                $token = $request->query($this->_config['parameter']);
            }

            $this->_token = $token ?: null;
        }

        return $this->_token;
    }

    /**
     * Decode JWT token.
     *
     * @param string $token JWT token to decode.
     * @return object|null The JWT's payload as a PHP object, null on failure.
     */
    protected function _decode($token)
    {
        try {
            $payload = JWT::decode($token, Security::salt(), $this->_config['allowedAlgs']);
            return $payload;
        } catch (Exception $e) {
            if (Configure::read('debug')) {
                throw $e;
            }
            $this->_error = $e;
        }
    }

    /**
     * Handles an unauthenticated access attempt. Depending on value of config
     * `unauthenticatedException` either throws the specified exception or returns
     * null.
     *
     * @param \Cake\Network\Request $request A request object.
     * @param \Cake\Network\Response $response A response object.
     * @return void
     * @throws \Cake\Network\Exception\UnauthorizedException Or any other
     *   configured exception.
     */
    public function unauthenticated(Request $request, Response $response)
    {
        if (!$this->_config['unauthenticatedException']) {
            return;
        }

        $message = $this->_error ? $this->_error->getMessage() : $this->_registry->Auth->_config['authError'];

        $exception = new $this->_config['unauthenticatedException']($message);
        throw $exception;
    }
}
