<?php

namespace CasbinAdapter\Database;

use Casbin\Model\Model;
use Casbin\Persist\Adapter as AdapterContract;
use TechOne\Database\Manager;
use Casbin\Persist\AdapterHelper;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Casbin\Persist\BatchAdapter;
use Casbin\Persist\UpdatableAdapter;
use Closure;
use Throwable;

/**
 * DatabaseAdapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract, FilteredAdapter, BatchAdapter, UpdatableAdapter
{
    use AdapterHelper;

    protected $config;

    protected $filtered;

    protected $connection;

    public $casbinRuleTableName = 'casbin_rule';

    public $rows = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->filtered = false;
        $this->connection = (new Manager($config))->getConnection();
        $this->initTable();
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        return $this->filtered;
    }

    /**
     * Sets filtered parameter.
     *
     * @param bool $filtered
     */
    public function setFiltered(bool $filtered): void
    {
        $this->filtered = $filtered;
    }

    public static function newAdapter(array $config)
    {
        return new static($config);
    }

    public function initTable()
    {
        $sql = file_get_contents(__DIR__.'/../migrations/'.$this->config['type'].'.sql');
        $sql = str_replace('%table_name%', $this->casbinRuleTableName, $sql);
        $this->connection->execute($sql, []);
    }

    public function savePolicyLine($ptype, array $rule)
    {
        $col['ptype'] = $ptype;
        foreach ($rule as $key => $value) {
            $col['v'.strval($key).''] = $value;
        }

        $colStr = implode(', ', array_keys($col));

        $name = rtrim(str_repeat('?, ', count($col)), ', ');

        $sql = 'INSERT INTO '.$this->casbinRuleTableName.'('.$colStr.') VALUES ('.$name.') ';

        $this->connection->execute($sql, array_values($col));
    }

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     */
    public function loadPolicy(Model $model): void
    {
        $rows = $this->connection->query('SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName.'');

        foreach ($rows as $row) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void
    {
        $columns = ['v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $sql = 'UPDATE ' . $this->casbinRuleTableName . ' SET ';
        $set = [];
        $values = [];
        foreach ($newPolicy as $key => $value) {
            array_push($set, $columns[$key] . '=?');
            $values[$key] = $value;
        }
        $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        //var_dump($set, $values);exit;
        $sql .= implode(', ', $set) . ' WHERE ';
        //var_dump($sql);exit;
        array_unshift($oldRule, $ptype);
        //$oldRule['p_type'] = $ptype;
        $where = [];
        //$whereValue = [];
        //var_dump($oldRule);exit;
        foreach ($oldRule as $key => $value) {
            array_push($where, $columns[$key] . '=?');
            $values[] = $value;
        }
        
        $sql .= implode(' AND ', $where);
        /*
        echo '<pre>';
        var_dump($sql);
        echo '<br />';
        var_dump($values);
        exit;
        */
        
        $this->connection->execute($sql, $values);
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
     */
    public function savePolicy(Model $model): void
    {
        foreach ($model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        foreach ($model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
    }

    /**
     * adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $this->savePolicyLine($ptype, $rule);
    }

    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $table = $this->casbinRuleTableName;
        $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $values = [];
        $sets = [];
        $columnsCount = count($columns);
        foreach ($rules as $rule) {
            $values = array_merge($values, array_pad($rule, $columnsCount, null));
            $sets[] = array_pad([], $columnsCount, '?');
        }
        $valuesStr = implode(', ', array_map(function ($set) {
            return '(' . implode(', ', $set) . ')';
        }, $sets));
        $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ')' .
            ' VALUES' . $valuesStr;
        $this->connection->query($sql, $values);
    }

    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        $this->connection->getPdo()->beginTransaction();
        try {
            foreach($rules as $rule) {
                $this->removePolicy($sec, $ptype, $rule);
            }
            $this->connection->getPdo()->commit();
        } catch (Throwable $e){
            $this->connection->getPdo()->rollback();
            throw $e;
        }
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';
        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
            $condition[] = 'v'.strval($key).' = :'.'v'.strval($key);
        }

        $sql = 'DELETE FROM '.$this->casbinRuleTableName.' WHERE '.implode(' AND ', $condition);

        $this->connection->execute($sql, $where);
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';
        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $fieldValues[$value - $fieldIndex]) {
                    $where['v'.strval($value)] = $fieldValues[$value - $fieldIndex];
                    $condition[] = 'v'.strval($value).' = :'.'v'.strval($value);
                }
            }
        }

        $sql = 'DELETE FROM '.$this->casbinRuleTableName.' WHERE '.implode(' AND ', $condition);

        $this->connection->execute($sql, $where);
    }

    /**
     * Loads only policy rules that match the filter from storage.
     *
     * @param Model $model
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        // if $filter is empty, load all policies
        if (is_null($filter)) {
            $this->loadPolicy($model);
            return;
        }
        // the basic sql
        $sql = 'SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName . ' WHERE ';
        
        if ($filter instanceof Filter) {
            $type = '';
            $filter = (array) $filter;
            // choose which ptype to use
            foreach($filter as $i => $v) {
                if (!empty($v)) {
                    array_unshift($filter[$i], $i);
                    $type = $i;
                    break;
                }
            }
            $items = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
            $temp = [];
            $values = [];
            foreach($items as $i => $item) {
                if (isset($filter[$type][$i]) && !empty($filter[$type][$i])) {
                    array_push($temp, $item . '=:' . $item);
                    $values[$item] = $filter[$type][$i];
                }
            }
            $sql .= implode(' and ', $temp);
            $rows = $this->connection->query($sql, $values);
        } elseif (is_string($filter)) {
            $sql .= $filter;
            $rows = $this->connection->query($sql);
        } elseif ($filter instanceof Closure) {
            $filter($this->connection, $sql, $this->rows);
        } else {
            throw new InvalidFilterTypeException('invalid filter type');
        }

        $rows = $rows ?? $this->rows;
        foreach($rows as $row) {
            $line = implode(', ', $row);
            $this->loadPolicyLine($line, $model);
        }
        $this->setFiltered(true);
    }
}
