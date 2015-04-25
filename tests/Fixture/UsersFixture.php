<?php
namespace ADmad\JwtAuth\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class UsersFixture extends TestFixture
{
    /**
     * fields property
     *
     * @var array
     */
    public $fields = [
        'id' => ['type' => 'integer'],
        'group_id' => ['type' => 'integer', 'null' => false],
        'user_name' => ['type' => 'string', 'null' => false],
        'email' => ['type' => 'string', 'null' => false],
        'password' => ['type' => 'string', 'null' => false],
        'created' => 'datetime',
        'updated' => 'datetime',
        '_constraints' => ['primary' => ['type' => 'primary', 'columns' => ['id']]]
    ];

    /**
     * records property
     *
     * @var array
     */
    public $records = [
        [
            'group_id' => 1, 'user_name' => 'admad',
            'email' => 'admad@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99',
            'created' => '2014-03-17 01:18:23', 'updated' => '2014-03-17 01:20:31'
        ],
        [
            'group_id' => 2, 'user_name' => 'mark',
            'email' => 'mark@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99',
            'created' => '2014-03-17 01:16:23', 'updated' => '2014-03-17 01:18:31'
        ],
        [
            'group_id' => 2, 'user_name' => 'jose',
            'email' => 'jose@example.com', 'password' => '5f4dcc3b5aa765d61d8327deb882cf99',
            'created' => '2014-03-17 01:20:23', 'updated' => '2014-03-17 01:22:31'
        ],
    ];
}
