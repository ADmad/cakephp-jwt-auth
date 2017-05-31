<?php
namespace ADmad\JwtAuth\Auth\Test\TestCase\Auth;

use ADmad\JwtAuth\Auth\JwtAuthenticate;
use Cake\Core\Configure;
use Cake\I18n\Time;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use Firebase\JWT\JWT;

/**
 * Test case for JwtAuthentication.
 */
class JwtAuthenticateTest extends TestCase
{
    public $fixtures = [
        'plugin.ADmad\JwtAuth.users',
        'plugin.ADmad\JwtAuth.groups',
    ];

    /**
     * setup.
     *
     * @return void
     */
    public function setUp()
    {
        parent::setUp();

        Security::salt('secret-key');

        $this->Registry = $this->getMockBuilder('Cake\Controller\ComponentRegistry')
            ->getMock();
        $this->auth = new JwtAuthenticate($this->Registry, [
            'userModel' => 'Users',
        ]);

        $this->token = JWT::encode(['sub' => 1], Security::salt());

        $this->response = $this->getMockBuilder('Cake\Network\Response')
            ->getMock();
    }

    /**
     * testConfig.
     *
     * @return void
     */
    public function testConfig()
    {
        $auth = new JwtAuthenticate($this->Registry, [
            'allowedAlgs' => ['RS256']
        ]);

        $this->assertEquals(['RS256'], $auth->config('allowedAlgs'));
    }

    /**
     * test authenticate token as query parameter.
     *
     * @return void
     */
    public function testAuthenticateTokenParameter()
    {
        $request = new Request('posts/index');

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
        $request = new Request('posts/index?token=' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $this->auth->config('parameter', 'tokenname');
        $request = new Request('posts/index?tokenname=' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = new Request('posts/index?wrongtoken=' . $this->token);
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
        $request = new Request('posts/index');

        $expected = [
            'id' => 1,
            'group_id' => 1,
            'user_name' => 'admad',
            'email' => 'admad@example.com',
            'created' => new Time('2014-03-17 01:18:23'),
            'updated' => new Time('2014-03-17 01:20:31'),
        ];
        $request->env('HTTP_AUTHORIZATION', 'Bearer ' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request->env('HTTP_AUTHORIZATION', 'WrongBearer ' . $this->token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $this->setExpectedException('UnexpectedValueException');
        $request->env('HTTP_AUTHORIZATION', 'Bearer foobar');
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
        $request = new Request('posts/index');

        $this->auth = new JwtAuthenticate($this->Registry, [
            'userModel' => 'Users',
            'parameter' => false
        ]);

        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $request = new Request('posts/index?token=' . $this->token);
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
        $token = JWT::encode($expected, Security::salt());
        $this->auth->config('queryDatasource', false);

        $request = new Request('posts/index');
        $request->env('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $request = new Request('posts/index?token=' . $token);
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
        $token = JWT::encode(['id' => 4], Security::salt());

        $request = new Request('posts/index');
        $request->env('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);

        $request = new Request('posts/index?token=' . $token);
        $result = $this->auth->getUser($request, $this->response);
        $this->assertFalse($result);
    }

    /**
     * test contain.
     *
     * @return void
     */
    public function testFindUserWithContain()
    {
        $request = new Request('posts/index');

        $expected = [
            'id' => 1,
            'group_id' => 1,
            'user_name' => 'admad',
            'email' => 'admad@example.com',
            'created' => new Time('2014-03-17 01:18:23'),
            'updated' => new Time('2014-03-17 01:20:31'),
            'group' => [
                'id' => 1,
                'title' => 'admin',
            ],
        ];
        $request->env('HTTP_AUTHORIZATION', 'Bearer ' . $this->token);

        $this->auth->config('contain', ['Groups']);
        $table = TableRegistry::get('Users');
        $table->belongsTo('Groups');

        $result = $this->auth->getUser($request, $this->response);
        $this->assertEquals($expected, $result);

        $this->setExpectedException('UnexpectedValueException');
        $request->env('HTTP_AUTHORIZATION', 'Bearer foobar');
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
        $this->assertFalse($this->auth->authenticate(new Request(), $this->response));
    }

    /**
     * test that with debug off for invalid token exception from JWT::decode()
     * is re-thrown.
     *
     * @expectedException DomainException
     */
    public function testExceptionForInvalidToken()
    {
        $request = new Request('posts/index');
        $request->env('HTTP_AUTHORIZATION', 'Bearer this.is.invalid');

        $result = $this->auth->getUser($request, $this->response);
    }

    /**
     * @expectedException Cake\Network\Exception\UnauthorizedException
     * @expectedExceptionMessage Auth error
     */
    public function testUnauthenticated()
    {
        $this->Registry->Auth = new \stdClass();
        $this->Registry->Auth->_config['authError'] = 'Auth error';

        $result = $this->auth->unauthenticated(new Request(), $this->response);
    }

    /**
     * test unauthenticated() doesn't throw exception is config `unauthenticatedException`
     * is set to falsey value.
     */
    public function testUnauthenticatedNoException()
    {
        $this->auth->config('unauthenticatedException', false);
        $this->assertNull($this->auth->unauthenticated(new Request(), $this->response));
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
        $request = new Request('posts/index');

        $request->env('HTTP_AUTHORIZATION', 'Bearer this.is.invalid');
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

        $request = new Request('posts/index');
        $request->env('HTTP_AUTHORIZATION', 'Bearer ' . $token);
        $result = $auth->getUser($request, $this->response);
        $this->assertEquals($payload, $result);

        $request = new Request('posts/index?token=' . $token);
        $result = $auth->getUser($request, $this->response);
        $this->assertEquals($payload, $result);
    }
}
