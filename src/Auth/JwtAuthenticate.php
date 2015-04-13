<?php
namespace ADmad\JwtAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\Utility\Security;
use \JWT;

/**
 * An authentication adapter for authenticating using JSON Web Tokens.
 *
 * {{{
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
 * }}}
 *
 * @copyright 2014 A. Sarela aka ADmad
 * @license MIT
 * @see http://jwt.io
 * @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
 */
class JwtAuthenticate extends BaseAuthenticate
{
    /**
     * Constructor.
     *
     * Settings for this object.
     *
     * - `parameter` - The url parameter name of the token. Defaults to `_token`.
     *   First $_SERVER['HTTP_AUTHORIZATION'] is checked for token value.
     *   It's value should be of form "Bearer <token>". If empty this query string
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
            'fields' => ['id' => 'id'],
            'unauthenticatedException' => '\Cake\Network\Exception\UnauthorizedException',
            'allowedAlgs' => ['HS256']
        ]);

        parent::__construct($registry, $config);
    }

    /**
     * Unused, since this is a stateless authentication provider.
     *
     * @param Request $request The request object.
     * @param Response $response Response object.
     * @return bool Always false.
     */
    public function authenticate(Request $request, Response $response)
    {
        return false;
    }

    /**
     * Get token information from the request.
     *
     * @param \Cake\Network\Request $request Request object.
     * @return bool|array Either false or an array of user information
     */
    public function getUser(Request $request)
    {
        $token = $this->_getToken($request);
        if ($token) {
            return $this->_findUser($token);
        }

        return false;
    }

    /**
     * Get token from header or query string
     *
     * @param \Cake\Network\Request $request Request object.
     * @return string|bool Token string if found else false
     */
    protected function _getToken($request)
    {
        $token = $request->env('HTTP_AUTHORIZATION');

        if (!$token && function_exists('getallheaders')) {
            $headers = getallheaders();
            if (isset($headers['Authorization']) &&
                substr($headers['Authorization'], 0, 7) === 'Bearer '
            ) {
                $token = $headers['Authorization'];
            }
        }

        if ($token) {
            return substr($token, 7);
        }

        if (!empty($this->_config['parameter']) &&
            isset($request->query[$this->_config['parameter']])
        ) {
            $token = $request->query($this->_config['parameter']);
        }

        return $token ? $token : false;
    }

    /**
     * Find a user record.
     *
     * @param string $token The token identifier.
     * @param string $password Unused password.
     * @return bool|array Either false on failure, or an array of user data.
     */
    protected function _findUser($token, $password = null)
    {
        $token = JWT::decode($token, Security::salt(), $this->_config['allowedAlgs']);

        // Token has full user record.
        if (isset($token->record)) {
            // Trick to convert object of stdClass to array. Typecasting to
            // array doesn't convert property values which are themselves objects.
            return json_decode(json_encode($token->record), true);
        }

        $fields = $this->_config['fields'];

        $table = TableRegistry::get($this->_config['userModel']);
        $conditions = [$table->aliasField($fields['id']) => $token->id];
        if (!empty($this->_config['scope'])) {
            $conditions = array_merge($conditions, $this->_config['scope']);
        }

        $query = $table->find('all')
            ->where($conditions)
            ->hydrate(false);

        if ($this->_config['contain']) {
            $table = $table->contain($contain);
        }

        $result = $query->first();
        if (empty($result)) {
            return false;
        }

        unset($result[$fields['password']]);
        return $result;
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

        $exception = new $this->_config['unauthenticatedException']($this->_registry->Auth->_config['authError']);
        throw $exception;
    }
}
