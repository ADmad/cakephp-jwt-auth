<?php
use Cake\Cache\Cache;
use Cake\Core\Configure;
use Cake\Core\Plugin;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\I18n;
use Cake\Log\Log;

require_once 'vendor/autoload.php';

// Path constants to a few helpful things.
define('DS', DIRECTORY_SEPARATOR);
define('ROOT', dirname(__DIR__) . DS);
define('CAKE_CORE_INCLUDE_PATH', ROOT . 'vendor' . DS . 'cakephp' . DS . 'cakephp');
define('CORE_PATH', ROOT . 'vendor' . DS . 'cakephp' . DS . 'cakephp' . DS);
define('CAKE', CORE_PATH . 'src' . DS);
define('APP', ROOT . 'tests' . DS . 'test_app' . DS);
define('TMP', sys_get_temp_dir() . DS);
define('CACHE', TMP);
define('LOGS', TMP);

$loader = new \Cake\Core\ClassLoader;
$loader->register();

$loader->addNamespace('TestApp', APP);

require_once CORE_PATH . 'config/bootstrap.php';

date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');

Configure::write('debug', true);
Configure::write('App', [
	'namespace' => 'App',
	'encoding' => 'UTF-8',
	'base' => false,
	'baseUrl' => false,
	'dir' => 'src',
	'webroot' => 'webroot',
	'www_root' => APP . 'webroot',
	'fullBaseUrl' => 'http://localhost',
	'imageBaseUrl' => 'img/',
	'jsBaseUrl' => 'js/',
	'cssBaseUrl' => 'css/',
	'paths' => [
		'plugins' => [APP . 'Plugin' . DS],
		'templates' => [APP . 'Template' . DS]
	]
]);
Configure::write('Session', [
	'defaults' => 'php'
]);

Cache::config([
	'_cake_core_' => [
		'engine' => 'File',
		'prefix' => 'cake_core_',
		'serialize' => true
	],
	'_cake_model_' => [
		'engine' => 'File',
		'prefix' => 'cake_model_',
		'serialize' => true
	],
	'default' => [
		'engine' => 'File',
		'prefix' => 'default_',
		'serialize' => true
	]
]);

// Ensure default test connection is defined
if (!getenv('db_class')) {
	putenv('db_class=Cake\Database\Driver\Sqlite');
	putenv('db_dsn=sqlite::memory:');
}

ConnectionManager::config('test', [
	'className' => 'Cake\Database\Connection',
	'driver' => getenv('db_class'),
	'dsn' => getenv('db_dsn'),
	'database' => getenv('db_database'),
	'username' => getenv('db_login'),
	'password' => getenv('db_password'),
	'timezone' => 'UTC'
]);

Log::config([
	'debug' => [
		'engine' => 'Cake\Log\Engine\FileLog',
		'levels' => ['notice', 'info', 'debug'],
		'file' => 'debug',
	],
	'error' => [
		'engine' => 'Cake\Log\Engine\FileLog',
		'levels' => ['warning', 'error', 'critical', 'alert', 'emergency'],
		'file' => 'error',
	]
]);

Plugin::load('ADmad/JwtAuth', ['path' => ROOT]);
