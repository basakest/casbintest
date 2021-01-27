<?php
require_once './vendor/autoload.php';

use Casbin\Enforcer;
use Casbin\Persist\Adapters\Filter;
use Casbin\Util\Log;
use CasbinAdapter\Database\FilterAdapter as FilterDatabaseAdapter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Casbin\Model\Model;
use CasbinAdapter\Database\Adapter;

$config = [
    'type'     => 'mysql', // mysql,pgsql,sqlite,sqlsrv
    'hostname' => '127.0.0.1',
    'database' => 'weibo',
    'username' => 'homestead',
    'password' => 'secret',
    'hostport' => '3306',
];
$model = Model::newModelFromFile('./model.conf');
$adapter = Adapter::newAdapter($config);
//不能带v
//$adapter->removePolicies('p', 'p', [['0' => 'jack'], ['0' => 'alice']]);
//$adapter->addPolicies('p', 'p', [['p', 'alice', 'data1', 'read'], ['p', 'jack', 'data1', 'write']]);
//$e = new Enforcer('./model.conf', $adapter);
$e = new Enforcer($model, $adapter);
//$e->addPermissionForUser('eve', 'data3', 'read');
//$e->addPolicy('bob', 'data1', 'read');exit;
//$e->enforce('alice', 'data1', 'read');exit;
//var_dump($e->enforce('alice', 'data1', 'read'));exit;
//var_dump($e->enforceWithMatcher('eval(alice)', 'alice', 'data1', 'read'));exit;
$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.
//$e->addPolicy('alice', 'data12', 'read');exit;
$e->clearPolicy();
var_dump($e->getPolicy());exit;
try {
    $filter = new Filter(['', '', 'read']);
    $e->loadFilteredPolicy($filter);
    var_dump($e->getPolicy());
    //var_dump($model['p']['p']->policy);
} catch (InvalidFilterTypeException $e) {
    echo $e->getMessage();
}
