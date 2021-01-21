<?php

namespace Tests;

use Casbin\Enforcer;
use CasbinAdapter\Database\Adapter as DatabaseAdapter;
use PHPUnit\Framework\TestCase;
use TechOne\Database\Manager;
use Casbin\Persist\Adapters\Filter;
class AdapterTest extends TestCase
{
    protected $config = [];

    protected function initConfig()
    {
        $this->config = [
            'type' => 'mysql', // mysql,pgsql,sqlite,sqlsrv
            /*
            'hostname' => $this->env('DB_PORT', '127.0.0.1'),
            'database' => $this->env('DB_DATABASE', 'weibo'),
            'username' => $this->env('DB_USERNAME', 'homestead'),
            'password' => $this->env('DB_PASSWORD', 'secret'),
            'hostport' => $this->env('DB_PORT', 3306),
            */
            'hostname' => '127.0.0.1',
            'database' => 'weibo',
            'username' => 'homestead',
            'password' => 'secret',
            'hostport' => 3306,
        ];
    }

    protected function initDb()
    {
        $tableName = 'casbin_rule';
        $conn = (new Manager($this->config))->getConnection();
        $conn->execute('DELETE FROM '.$tableName);
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'alice\', \'data1\', \'read\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'bob\', \'data2\', \'write\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'data2_admin\', \'data2\', \'read\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'data2_admin\', \'data2\', \'write\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1) VALUES ( \'g\', \'alice\', \'data2_admin\') ');
    }

    protected function getEnforcer()
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);
        $this->initDb();
        return new Enforcer(__DIR__.'/rbac_model.conf', $adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }
    
    public function testLoadFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $e->loadFilteredPolicy(new Filter(['alice']));
        $model = $e->getModel();
        $this->assertTrue(!empty($model['p']['p']->policy));
        $model->clearPolicy();

        $e->loadFilteredPolicy(new Filter(['xxxxx12v']));
        $model = $e->getModel();
        $this->assertFalse(!empty($model['p']['p']->policy));
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));

        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testAddPolicies()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));
        $this->assertFalse($e->enforce('eve', 'data3', 'write'));

        $e->addPolicies([['eve', 'data3', 'read'], ['eve', 'data3', 'write']]);
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
        $this->assertTrue($e->enforce('eve', 'data3', 'write'));
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));

        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);

        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemovePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPolicies([['alice', 'data5', 'read'], ['alice', 'data5', 'write']]);
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $this->assertTrue($e->enforce('alice', 'data5', 'write'));
        $e->removePolicies([['alice', 'data5', 'read'], ['alice', 'data5', 'write']]);
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $this->assertFalse($e->enforce('alice', 'data5', 'write'));
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(1, 'data2', 'read');

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(2, 'write');

        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}