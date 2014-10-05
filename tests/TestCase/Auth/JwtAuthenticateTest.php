<?php
namespace ADmad\JwtAuth\Auth\Test\TestCase\Auth;

use ADmad\JwtAuth\Auth\JwtAuthenticate;
use Cake\Controller\Component\AuthComponent;
use Cake\Controller\Controller;
use Cake\I18n\Time;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use \JWT;

/**
 * Test case for JwtAuthentication
 */
class JwtAuthenticateTest extends TestCase {

	public $fixtures = ['plugin.ADmad\JwtAuth.users'];

/**
 * setup
 *
 * @return void
 */
	public function setUp() {
		parent::setUp();

		$this->Registry = $this->getMock('Cake\Controller\ComponentRegistry');
		$this->auth = new JwtAuthenticate($this->Registry, [
			'userModel' => 'Users'
		]);

		$this->token = JWT::encode(['id' => 1], Security::salt());

		$this->response = $this->getMock('Cake\Network\Response');
	}

/**
 * test authenticate token as query parameter
 *
 * @return void
 */
	public function testAuthenticateTokenParameter() {
		$request = new Request('posts/index');

		$result = $this->auth->getUser($request, $this->response);
		$this->assertFalse($result);

		$expected = array(
			'id' => 1,
			'user_name' => 'admad',
			'email' => 'admad@example.com',
			'created' => new Time('2014-03-17 01:18:23'),
			'updated' => new Time('2014-03-17 01:20:31')
		);
		$request = new Request('posts/index?_token=' . $this->token);
		$result = $this->auth->getUser($request, $this->response);
		$this->assertEquals($expected, $result);

		$this->auth->config('parameter', 'tokenname');
		$request = new Request('posts/index?tokenname=' . $this->token);
		$result = $this->auth->getUser($request, $this->response);
		$this->assertEquals($expected, $result);
	}

/**
 * test authenticate token as request header
 *
 * @return void
 */
	public function testAuthenticateTokenHeader() {
		$request = new Request('posts/index');

		$expected = array(
			'id' => 1,
			'user_name' => 'admad',
			'email' => 'admad@example.com',
			'created' => new Time('2014-03-17 01:18:23'),
			'updated' => new Time('2014-03-17 01:20:31')
		);
		$request->env('HTTP_AUTHORIZATION', 'Bearer ' . $this->token);
		$result = $this->auth->getUser($request, $this->response);
		$this->assertEquals($expected, $result);

		$this->setExpectedException('UnexpectedValueException');
		$request->env('HTTP_AUTHORIZATION', 'Bearer foobar');
		$result = $this->auth->getUser($request, $this->response);
		$this->assertFalse($result);
	}

/**
 * test authenticate token with user record
 *
 * @return void
 */
	public function testAuthenticateWithUserRecord() {
		$request = new Request('posts/index');

		$expected = [
			'id' => 99,
			'username' => 'ADmad',
			'group' => ['name' => 'admin']
		];
		$request->env(
			'HTTP_AUTHORIZATION',
			'Bearer ' . JWT::encode(['record' => $expected], Security::salt())
		);
		$result = $this->auth->getUser($request, $this->response);
		$this->assertEquals($expected, $result);
	}

}
