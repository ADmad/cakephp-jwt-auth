<?php
declare(strict_types=1);

namespace ADmad\JwtAuth\Auth\Test\TestCase\Auth;

use ADmad\JwtAuth\Auth\JwtAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Core\Configure;
use Cake\Http\Exception\UnauthorizedException;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\I18n\FrozenTime;
use Cake\I18n\Time;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use DomainException;
use Firebase\JWT\JWT;

/**
 * Test case for JwtAuthentication.
 */
class JwtAuthenticateTest extends TestCase
{
    public $fixtures = [
        'plugin.ADmad\JwtAuth.Users',
        'plugin.ADmad\JwtAuth.Groups',
    ];

    /**
     * setup.
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        Security::setSalt('secret-key');

        $this->Registry = new ComponentRegistry();
        $this->auth = new JwtAuthenticate($this->Registry, [
            'userModel' => 'Users',
        ]);
        $this->Registry->Auth = $this->auth;

        $this->token = JWT::encode(['sub' => 1], Security::getSalt());

        $this->response = $this->getMockBuilder(Response::class)
            ->getMock();
    }

    /**
     * testConfig.
     *
     * @return void
     */
    public function testConfig()
    {
        $auth = new JwtAuthenticate($this->Registry, []);
        $this->assertEquals(['HS256'], $auth->getConfig('allowedAlgs'));

        $auth = new JwtAuthenticate($this->Registry, [
            'allowedAlgs' => ['RS256'],
        ]);
        $this->assertEquals(['RS256'], $auth->getConfig('allowedAlgs'));
    }

    /**
     * test authenticate token as query parameter.
     *
     * @return void
     */
    public function testAuthenticateTokenParameter()
    {
        $request = new ServerRequest();

        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $expected = [
            'id' => 1,
            'group_id' => 1,
            'user_name' => 'admad',
            'email' => 'admad@example.com',
            'created' => new FrozenTime('2014-03-17 01:18:23'),
            'updated' => new FrozenTime('2014-03-17 01:20:31'),
        ];
        $request = new ServerRequest(['url' => 'posts/index?token=' . $this->token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $this->auth->setConfig('parameter', 'tokenname');
        $request = new ServerRequest(['url' => 'posts/index?tokenname=' . $this->token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = new ServerRequest(['url' => 'posts/index?wrongtoken=' . $this->token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * test authenticate token as request header.
     *
     * @return void
     */
    public function testAuthenticateTokenHeader()
    {
        $request = new ServerRequest();

        $expected = [
            'id' => 1,
            'group_id' => 1,
            'user_name' => 'admad',
            'email' => 'admad@example.com',
            'created' => new FrozenTime('2014-03-17 01:18:23'),
            'updated' => new FrozenTime('2014-03-17 01:20:31'),
        ];
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer ' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = $request->withEnv('HTTP_AUTHORIZATION', 'WrongBearer ' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $this->expectException('UnexpectedValueException');
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer foobar');
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * test authenticate no token present in header "parameter" option disabled.
     *
     * @return void
     */
    public function testAuthenticateNoHeaderWithParameterDisabled()
    {
        $request = new ServerRequest();

        $this->auth = new JwtAuthenticate($this->Registry, [
            'userModel' => 'Users',
            'parameter' => false,
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $request = new ServerRequest(['url' => 'posts/index?token=' . $this->token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * test returning payload without querying database.
     *
     * @return void
     */
    public function testQueryDatasourceFalse()
    {
        $expected = [
                'id' => 99,
                'username' => 'ADmad',
                'group' => ['name' => 'admin'],
        ];
        $token = JWT::encode($expected, Security::getSalt());
        $this->auth->setConfig('queryDatasource', false);

        $request = new ServerRequest();
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = new ServerRequest(['url' => 'posts/index?token=' . $token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);
    }

    /**
     * test for valid token but no matching user found in db.
     *
     * @return void
     */
    public function testWithValidTokenButNoUserInDb()
    {
        $token = JWT::encode(['id' => 4], Security::getSalt());

        $request = new ServerRequest();
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $request = new ServerRequest(['url' => 'posts/index?token=' . $token]);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * Test that authenticated() always returns false.
     *
     * @return void
     */
    public function testAuthenticated()
    {
        $this->assertFalse($this->auth->authenticate(new ServerRequest(), $this->response));
    }

    /**
     * test that with debug off for invalid token exception from JWT::decode()
     * is re-thrown.
     */
    public function testExceptionForInvalidToken()
    {
        $this->expectException(DomainException::class);

        $request = new ServerRequest();
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer this.is.invalid');

        $this->auth->getUser($request, $this->response);
    }

    /**
     * testUnauthenticated
     */
    public function testUnauthenticated()
    {
        $this->Registry->Auth->setConfig('authError', 'Auth error');

        $exceptionClass = UnauthorizedException::class;
        if (!class_exists(UnauthorizedException::class)) {
            $exceptionClass = 'Cake\Network\Exception\UnauthorizedException';
        }
        $this->expectException($exceptionClass);
        $this->expectExceptionMessage('Auth error');

        $result = $this->auth->unauthenticated(new ServerRequest(), $this->response);
    }

    /**
     * test unauthenticated() doesn't throw exception is config `unauthenticatedException`
     * is set to falsey value.
     */
    public function testUnauthenticatedNoException()
    {
        $this->auth->setConfig('unauthenticatedException', false);
        $this->assertNull($this->auth->unauthenticated(new ServerRequest(), $this->response));
    }

    /**
     * test that getUser() returns false instead of throwing exception with
     * invalid token when debug is off.
     *
     * @return void
     */
    public function testWithInvalidToken()
    {
        Configure::write('debug', false);
        $request = new ServerRequest();

        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer this.is.invalid');
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * test using custom key for decoding jwt.
     *
     * @return void
     */
    public function testCustomKey()
    {
        $key = 'my-custom-key';
        $auth = new JwtAuthenticate($this->Registry, [
            'key' => $key,
            'queryDatasource' => false,
        ]);

        $payload = ['sub' => 100];
        $token = Jwt::encode($payload, $key);

        $request = new ServerRequest();
        $request = $request->withEnv('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $auth->getUser($request, $this->response);
        $this->assertEquals($payload, $result);

        $request = new ServerRequest(['url' => '/posts/index?token=' . $token]);
        $result = $auth->getUser($request, $this->response);
        $this->assertEquals($payload, $result);
    }

    /**
     * test authenticate token as cookie.
     *
     * @return void
     */
    public function testAuthenticateCookie()
    {
        $request = new ServerRequest();

        $this->auth = new JwtAuthenticate($this->Registry, [
            'userModel' => 'Users',
            'cookie' => 'jwt',
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $expected = [
            'id' => 1,
            'group_id' => 1,
            'user_name' => 'admad',
            'email' => 'admad@example.com',
            'created' => new Time('2014-03-17 01:18:23'),
            'updated' => new Time('2014-03-17 01:20:31'),
        ];

        $request = new ServerRequest([
            'url' => 'posts/index',
            'cookies' => ['jwt' => $this->token],
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $this->auth->setConfig('cookie', 'tokenname');
        $request = new ServerRequest([
            'url' => 'posts/index',
            'cookies' => ['tokenname' => $this->token],
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = new ServerRequest([
            'url' => 'posts/index',
            'cookies' => ['wrongtoken' => $this->token],
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }
}
