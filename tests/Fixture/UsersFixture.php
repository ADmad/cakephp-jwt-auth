<?php
namespace ADmad\JwtAuth\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class UsersFixture extends TestFixture {

/**
 * fields property
 *
 * @var array
 */
	public $fields = array(
		'id' => array('type' => 'integer'),
		'user_name' => array('type' => 'string', 'null' => false),
		'email' => array('type' => 'string', 'null' => false),
		'password' => array('type' => 'string', 'null' => false),
		'created' => 'datetime',
		'updated' => 'datetime',
		'_constraints' => ['primary' => ['type' => 'primary', 'columns' => ['id']]]
	);

/**
 * records property
 *
 * @var array
 */
	public $records = array(
		array('user_name' => 'admad', 'email' => 'admad@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99', 'created' => '2014-03-17 01:18:23', 'updated' => '2014-03-17 01:20:31'),
		array('user_name' => 'mark', 'email' => 'mark@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99', 'created' => '2014-03-17 01:16:23', 'updated' => '2014-03-17 01:18:31'),
		array('user_name' => 'jose', 'email' => 'jose@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99', 'created' => '2014-03-17 01:20:23', 'updated' => '2014-03-17 01:22:31'),
	);
}
