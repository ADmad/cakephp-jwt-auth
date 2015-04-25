<?php
namespace ADmad\JwtAuth\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

/**
 * Class GroupsFixture
 *
 */
class GroupsFixture extends TestFixture
{

    /**
     * fields property
     *
     * @var array
     */
    public $fields = [
        'id' => ['type' => 'integer'],
        'title' => ['type' => 'string'],
        '_constraints' => ['primary' => ['type' => 'primary', 'columns' => ['id']]]
    ];

    /**
     * records property
     *
     * @var array
     */
    public $records = [
        ['title' => 'admin'],
        ['title' => 'moderator'],
    ];
}
