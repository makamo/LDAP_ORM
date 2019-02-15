<?php namespace LdapOrm;

use Exception;

/**
 * LdapOrm is a class that enhances the built in LdapOrm commands in
 *
 * @author  Brad Vernon <bradbury.vernon@gmail.com>
 * @category  LDAP
 * @version  0.1
 */
class LdapOrm
{
    /**
     * LDAP schema - queried on connect
     *
     * @var array
     */
    public $_schema = null;
    /**
     * Default LDAP Server
     *
     * @var string
     */
    protected $server = '';
    /**
     * Default LDAP port - Used for server/server_backup
     *
     * @var integer
     */
    protected $port = 389;
    /**
     * LDAP Connection resource
     *
     * @var resource
     */
    protected $_connection = NULL;
    /**
     * LDAP Error holder
     *
     * @var null
     */
    protected $error = null;
    /**
     * Base DN to use, set in functions
     *
     * @var string
     */
    protected $_dn;
    /**
     * @var array   Schama Attributes
     */
    protected $_schema_attribs = [];
    /**
     * Currently connected to LDAP server
     *
     * @var bool
     */
    protected $_connected = false;
    /**
     * Attributes to always return for all searches and queries
     * Default: * or everything
     *
     * @var array
     */
    protected $_default_query_fields = ['*'];
    /**
     * Query params
     *
     * @var array
     */
    protected $_query = [
        'limit' => false,
        'conditions' => '(objectClass=*)',
        'fields' => [],
        'hasMany' => false,
        'belongsTo' => false,
        'order' => false
    ];
    /**
     * $Ldap person key
     *
     * @var string
     */
    protected $ldap_person_key = 'person';
    /**
     * Ldap group key
     *
     * @var string
     */
    protected $ldap_group_key = 'group';

    /**
     * @param string $host server IP or domain
     * @param int $port port   default: 389
     * @param int $ldap_version ldap version to use     default: 3
     * @throws \Exception
     */
    public function __construct($host, $port = 389, $ldap_version = 3)
    {
        ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, $ldap_version);
        $this->server = $host;
        $this->port = $port;
        $this->connect();
    }

    /**
     * Connect to ldap_default
     *
     * If default connection not found try backup ldap server
     *
     * @return bool
     * @throws \Exception
     */
    protected function connect()
    {
        if (!is_null($this->_connection)) {
            return true;
        }

        $this->_connection = ldap_connect($this->server, $this->port);

        if (!is_resource($this->_connection)) {
            throw new Exception('Unable to connect to server ' . $this->server);
        }

        if (is_null($this->_schema_attribs)) {
            $this->getLDAPschemaAttribs();
        }

        return true;
    }

    /**
     * Get LDAP Schema
     *
     * @return bool
     */
    private function getLDAPschemaAttribs()
    {
        try {
            $schema_search = ldap_read($this->_connection,
                'cn=Subschema', '(objectClass=*)', ['attributetypes'], 0, 0, 0, LDAP_DEREF_ALWAYS);
            $schema_entries = ldap_get_entries($this->_connection, $schema_search);
        } catch (Exception $e) {
            $this->setError("Unable to fetch schema");

            return false;
        }

        if (empty($schema_entries[0]['attributetypes'])) {
            $this->setError("Unable to fetch schema attribute types");

            return false;
        }

        foreach ($schema_entries[0]['attributetypes'] as $attr) {
            $exp = explode("'", $attr);
            if (count($exp) < 2) {
                continue;
            }

            $this->_schema_attribs[$exp[1]] = (count($exp) > 3) ? $exp[3] : '';
        }

        return true;
    }

    /**
     * Set error message to class variable
     *
     * @param bool|string $msg custom message passed
     */
    protected function setError($msg = false)
    {
        $backtrace = debug_backtrace();
        $this->error['file'] = $backtrace[0]['file'];
        $this->error['line'] = $backtrace[0]['line'];

        if (!$msg) {
            $this->error['ldap_error'] = ldap_error($this->_connection);
        } else {
            $this->error['msg'] = $msg;
            $this->error['ldap_error'] = ldap_error($this->_connection);
            if ($this->error['ldap_error'] == 'Success') {
                unset($this->error['ldap_error']);
            }
        }
    }

    /**
     * Enable special functions such as 'findBy{Attribute}' and
     *  findAllBy{Attribute}
     *
     * @param $method
     * @param $attrs
     * @return mixed|null
     * @throws Exception
     */
    public function __call($method, $attrs = [])
    {
        if (empty($attrs)) {
            return null;
        }

        if (strpos(strtolower($method), 'findby') !== false) {
            $key = substr($method, strlen('findby'));
            $key = strtolower($key[0]) . substr($key, 1);
            $search = $attrs[0];

            if (isset($attrs[1])) {
                $this->_dn = $attrs[1];
            }

            return $this->find('first', ['conditions' => "{$key}={$search}"]);
        }

        if (strpos(strtolower($method), 'findallby') !== false) {
            $key = substr($method, strlen('findallby'));
            $key = strtolower($key[0]) . substr($key, 1);
            $search = $attrs[0];

            if (isset($attrs[1])) {
                $this->_dn = $attrs[1];
            }

            return $this->find('all', ['conditions' => "{$key}={$search}"]);
        }

        return null;
    }

    /**
     * Find records in ldap
     *
     * @param string $type first, all, count, list
     * @param array $queryData conditions, fields, limit, order, hasMany, belongsTo
     * @param bool $dn
     * @return mixed
     */
    public function find($type = 'all', $queryData = [], $dn = false)
    {
        if (!in_array($type, ['first', 'all', 'count', 'list'])) {
            $this->setError('Find type must be: first, all, count, or list');

            return false;
        }

        if ($dn) {
            $this->_dn = $dn;
        }

        if ($type == 'first') {
            $this->_query['limit'] = 1;
        }

        if (!empty($queryData['conditions'])) {
            $this->_query_builder($queryData['conditions']);
        }

        if (!empty($queryData['fields'])) {
            $this->_field_builder($queryData['fields']);
        }

        if (!$sr = @ldap_search($this->_connection,
            $this->_dn, $this->_query['conditions'],
            $this->_query['fields'], 0, $this->_query['limit'])
        ) {
            $this->setError("No records found");

            return false;
        }

        if ($type == "count") {
            return ldap_count_entries($this->_connection, $sr);
        }

        /** @noinspection PhpDeprecationInspection */
        ldap_sort($this->_connection, $sr, $this->_query['order']);

        $spl_dn = $this->dnToArray($this->_dn, false);

        $results = $this->_ldapFormat(@ldap_get_entries($this->_connection, $sr), $spl_dn[0]);

        if (empty($results)) {
            $this->setError("No records found");

            return false;
        }

        if ($type == "list") {
            return $this->_build_list($queryData, $results, $spl_dn[0]);
        }

        if (!empty($queryData['belongsTo'])) {
            $results = $this->_build_belongsTo($results, $queryData['belongsTo']);
        }

        if (!empty($queryData['hasMany'])) {
            $results = $this->_build_hasMany($results, $queryData['hasMany']);
        }

        if ($type == "first") {
            return $results[0];
        }

        return $results;
    }

    /**
     * Converts a human query to
     *
     * @todo enhance ability to parse complex strings
     * @param string $search search query string (ie "cn=green & gidNumber=3242442")
     * @return string ldap compatible
     */
    protected function _query_builder($search = '')
    {
        if (empty($search)) {
            return;
        }

        if (is_array($search)) {
            $this->_query['conditions'] = $this->search_format($search);

            return;
        }
        $qType = null;
        if (strpos($search, " AND ") !== false) {
            $str_exp = explode(" AND ", $search);
            $qType = 'and';
        }

        if (strpos($search, " OR ") > 0) {
            $str_exp = explode(" OR ", $search);
            $qType = 'or';
        }

        if (!isset($str_exp)) {
            $this->_query['conditions'] = "($search)";

            return;
        }

        $string = '';
        foreach ($str_exp as $s) {
            $string .= "($s)";
        }

        if ($qType == "and") {
            $filter_string = "(&$string)";
        } else {
            $filter_string = "(|$string)";
        }

        $this->_query['conditions'] = $filter_string;

        return;
    }

    /**
     * Create ldap compatible filter for searching contact attributes
     *
     * Filter Examples:
     *                    (cn=Babs Jensen)
     *                (!(cn=Tim Howes))
     *                (&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))
     *
     *                    a filter checking whether the "cn" attribute contained
     *                    a value with the character "*" anywhere in it would be represented as
     *                    "(cn=*\2a*)"
     *
     * @param array|object $filtered
     * @param bool $and
     * @return  string            full ldap filter string
     * @access    protected
     */
    protected function search_format($filtered, $and = false)
    {
        $string = '';
        $i = 0;

        if (count($filtered) == 0) {
            return "(objectClass=*)";
        }

        foreach ($filtered as $key => $val) {
            $string .= "($key=$val)";
            $i++;
        }

        if ($i > 1) {
            if ($and) {
                $filter_string = "(&$string)";
            } else {
                $filter_string = "(|$string)";
            }
        } else {
            $filter_string = "$string";
        }

        return $filter_string;
    }

    /**
     * Field builder
     * User if $queryData is not an array
     *
     * @param array|string $fields
     * @return array
     */
    protected function _field_builder($fields = [])
    {
        if (!is_array($fields) || empty($fields)) {
            $fields = [];
        }

        if (is_string($fields)) {
            $fields = array_map('trim', explode(",", $fields));
        }

        return $this->_query['fields'] = array_merge($fields, $this->_default_query_fields);
    }

    /**
     * Convert dn string to array
     *
     * @param string $input dn path
     * @param bool $withAttribs
     * @return      array        dn in array form
     * @access        public
     */
    public function dnToArray($input, $withAttribs = true)
    {
        $out = [];
        $str_exp = explode(',', $input);
        foreach ($str_exp as $sec) {
            list($key, $val) = explode('=', $sec);

            if ($withAttribs) {
                if (isset($out[$key])) {
                    if (is_array($out[$key])) {
                        array_push($out[$key], $val);
                    } else {
                        $out[$key] = [$out[$key], $val];
                    }

                } else {
                    $out[$key] = $val;
                }
            } else {
                $out[] = $val;
            }

        }

        return $out;
    }

    /**
     * Clean LDAP results to be just KEY => VALUE
     * Removes "count" from return
     *
     * @param array $data search results
     * @param string $base base ou (person,group,alias)
     * @return array|bool
     */
    protected function _ldapFormat($data, $base)
    {
        $res = [];
        foreach ($data as $key => $row) {
            if ($key === 'count')
                continue;
            foreach ($row as $key1 => $param) {
                if ($key1 === 'dn') {
                    $res[$key][$key1] = $param;
                    continue;
                }
                if (!is_numeric($key1))
                    continue;
                if ($row[$param]['count'] === 1)
                    $res[$key][$param] = $row[$param][0];
                else {
                    foreach ($row[$param] as $key2 => $item) {
                        if ($key2 === 'count')
                            continue;
                        $res[$key][$param][] = $item;
                    }
                }
            }
        }
        foreach ($res as $k => $v) {
            $out[$k] = [ucwords($base) => $v];
        }
        unset($res);

        if (isset($out)) {
            return $out;
        }

        return false;
    }

    /**
     * Build list of results
     * Primarily used in select fields or link list
     *
     * @param array $queryData $this->find query condition array
     * @param array $results $this->find results
     * @param string $base person, group, alias
     * @return  array
     */
    protected function _build_list($queryData, $results, $base)
    {
        $key = null;
        switch ($base) {
            case "person":
                $key = $this->ldap_person_key;
                break;
            case "group":
                $key = $this->ldap_group_key;
                break;
        }
        $field = current($queryData['fields']);
        $out = [];
        foreach ($results as $r) {
            if (isset($r[strtolower($field)])) {
                $out[$r[$key]] = $r[strtolower($field)];
            } else {
                $out[$r[$key]] = '';
            }
        }

        return $out;
    }

    /**
     * Build belongsTo results
     *
     * @param array $result results from $this->find()
     * @param array $belongsTo belongsTo conditions: on, fields, base,
     * @return  array
     */
    protected function _build_belongsTo($result = [], $belongsTo = [])
    {
        if (!is_array($result)) {
            return [];
        }

        foreach ($result as $k => $v) {
            foreach ($v as $base => $data) {

                $result_key = strtolower(key($belongsTo['on']));
                $belongsTo_key = current($belongsTo['on']);

                if (isset($belongsTo['fields'])) {
                    $find['fields'] = $this->_field_builder($belongsTo['fields']);
                }

                $belongsTo_dn = $this->dnToArray($belongsTo['base'], false);
                $belongsTo_base = $belongsTo_dn[0];

                $found = [];

                if (is_array($data[$result_key])) {

                    foreach ($data[$result_key] as $r) {
                        $find['conditions'] = "{$belongsTo_key}={$r}";

                        if ($belongsTo_key == 'dn') {
                            $found[] = $this->findByDn($r, $find['fields']);
                        } else {
                            $found[] = $this->find('all', $find, $belongsTo_dn);
                        }
                    }

                } else {
                    if ($belongsTo_key == 'dn') {
                        $found = $this->findByDn($data[$result_key]);
                    } else {
                        $find['conditions'] = "{$belongsTo_key}={$data[$result_key]}";
                        $found = $this->find('all', $find, $belongsTo_dn);
                        $find['conditions'] = "{$belongsTo_key}={$data[$result_key]}";
                    }
                }

                if (!empty($found)) {
                    $result[$k][$belongsTo_base] = $found;
                }

            }
        }

        return $result;
    }

    /**
     * Get specific DN and attributes
     *
     * @param string $dn DN string of record
     * @param array $only return only these attribs
     * @return array|bool
     */
    public function findByDn($dn, $only = ['*'])
    {
        if (!$r = @ldap_read($this->_connection, $dn, 'objectClass=*', $only)) {
            $this->setError();

            return false;
        }

        $results = @ldap_get_entries($this->_connection, $r);

        $out = $this->clearCounts($results[0]);
        $out['dn'] = $dn;

        return $out;
    }

    /**
     * Clear counts from returned result v2
     *
     * @param array $input result to clean
     * @return      array
     */
    public function clearCounts($input)
    {
        $new = [];

        foreach ($input as $k => $v) {
            if (!is_numeric($k)) {
                if (count($v) == 2) {
                    $new[$k] = $v[0];
                }
                if (count($v) > 2) {
                    unset($v['count']);
                    $new[$k] = $v;
                }
            }
        }

        return $new;
    }

    /**
     * Build hasMany output
     *
     * @param array $result results from $this->find()
     * @param array $hasMany hasMany conditions: on, fields, base,
     * @return array|bool
     */
    protected function _build_hasMany($result = [], $hasMany = [])
    {
        if (!is_array($result)) {
            return false;
        }
        foreach ($result as $k => $v) {
            foreach ($v as $base => $data) {
                $result_key = strtolower(key($hasMany['on']));
                $hasMany_key = current($hasMany['on']);
                if (isset($hasMany['fields'])) {
                    $find['fields'] = $this->_field_builder($hasMany['fields']);
                } else {
                    $find['fields'] = [];
                }
                $hasMany_dn = $this->dnToArray($hasMany['base'], false);
                $hasMany_base = $hasMany_dn[0];
                if (is_array($data[$result_key])) {
                    foreach ($data[$result_key] as $r) {
                        $find['conditions'] = "{$hasMany_key}={$r}";
                        if ($hasMany_key == 'dn') {
                            $found = $this->findByDn($r, $find['fields']);
                        } else {
                            $found = $this->find('all', $find, $hasMany_dn);
                        }
                    }
                } else {
                    $find['conditions'] = "{$hasMany_key}={$result_key}";
                    $found = $this->find('all', $find, $hasMany['base']);
                }
                if (!empty($found)) {
                    $result[$k][$hasMany_base] = $found;
                }
            }
        }

        return $result;
    }

    /**
     * Close connection on end of script running
     */
    public function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Disconnect from LDAP server
     */
    public function disconnect()
    {
        if (is_resource($this->_connection)) {
            ldap_unbind($this->_connection);
        }
    }

    /**
     * Set Server connection settings
     *
     * @param array $settings
     */
    public function setConnectionSettings($settings = [])
    {
        $this->server = $settings;
    }

    /**
     * Return if currently bound to a server
     *
     * @return bool
     */
    public function isConnected()
    {
        return $this->_connected;
    }

    /**
     * Ldap standard bind
     *
     * @param $user
     * @param $pass
     * @return  bool        true/false
     * @throws \Exception
     */
    public function bind($user, $pass)
    {
        if (is_null($this->_connection)) {
            $this->connect();
        }

        if (!@ldap_bind($this->_connection, $user, $pass)) {
            $this->setError();

            return false;
        }

        $this->_connected = true;

        return true;
    }

    /**
     * Bind to ldap server with SASL support
     *
     * @param string $uid username
     * @param null $pass
     * @param string $method
     * @return bool        true/false
     */
    public function bindSasl($uid = null, $pass = null, $method = 'GSSAPI')
    {
        if ($method == 'GSSAPI') {
            $type = 'GSSAPI';

            if (!empty($uid)) {
                $b = ldap_sasl_bind($this->_connection, NULL, NULL, 'GSSAPI', NULL, NULL, 'u:' . $uid);
            } else {
                $b = ldap_sasl_bind($this->_connection, NULL, NULL, 'GSSAPI', NULL, NULL, "");
            }

        } else {
            $type = 'PLAIN';

            if (!$uid || !$pass) {
                $this->setError('uid or pass not provided.');

                return false;
            }

            $b = ldap_sasl_bind($this->_connection, NULL, $pass, 'DIGEST-MD5', NULL, $uid);
        }

        if (!$b) {
            $this->setError("SASL {$type} bind for {$uid} failed");

            return false;
        }

        $this->_connected = true;

        return true;
    }

    /**
     * SASL bind find current users DN listing
     *
     * Requires patch to be added to local install:
     * http://cvsweb.netbsd.org/bsdweb.cgi/pkgsrc/databases/php-ldap/files/ldap-ctrl-exop.patch
     *
     * @return      string        LDAP DN
     */
    public function whoAmI()
    {
        if (function_exists('ldap_exop_whoami')) {
            $result = '';
            ldap_exop_whoami($this->_connection, $result);

            return $result;
        }

        return null;
    }

    /**
     * If error is found properly format error for best readability
     *
     * @return mixed
     */
    public function showError()
    {
        if (empty($this->error)) {
            return null;
        }

        if (is_array($this->error)) {
            echo "<span style='color:red'>Error:</span><pre>";
            print_r($this->error);
            echo "</pre>";
        } else {
            echo "<span style='color:red'>Error: " . $this->error . "</span>";
        }

        return;
    }

    /**
     * Get Last Error
     *
     * @return null
     */
    public function getLastError()
    {
        if (empty($this->error)) {
            return null;
        }

        return $this->error;
    }

    /**
     * Add new record to LDAP
     *
     * @param bool $dn new dn of record
     * @param array $data records attributes
     * @param bool $strict Strict mode checks the schema for attribute and if attrib missing fails.
     *                              disabled strict mode just unsets the attribute and continues saving
     * @return bool
     */
    public function save($dn = false, $data = [], $strict = false)
    {
        if (!$dn || !is_array($data)) {
            $this->setError("Input values empty");

            return false;
        }

        foreach ($data as $k => $v) {
            if (!isset($this->_schema_attribs[$k])) {

                if ($strict) {
                    $this->setError("Attribute {{$k}} does not exist and strict mode is active");

                    return false;
                }

                unset($data[$k]);
            }
        }

        if ($this->dnExists($dn)) {
            $this->setError('DN already exists');

            return false;
        }

        if (!@ldap_add($this->_connection, $dn, $data)) {
            $this->setError();

            return false;
        }

        return $dn;
    }

    /**
     * Checks if DN exists
     * Return True or False
     *
     * @paramstring $dn record DN
     * @paramstring $filter
     * @param $dn
     * @param string $filter
     * @return    bool
     */
    public function dnExists($dn, $filter = "objectClass=*")
    {
        if (!$sr = @ldap_read($this->_connection, $dn, $filter)) {
            return false;
        }

        $l = ldap_get_entries($this->_connection, $sr);

        if (!isset($l['count']) || $l['count'] < 1) {
            return false;
        }

        return true;
    }

    /**
     * Update Existing record.
     *
     * if "objectClass" attribute exists the ldap_modify will be used,
     * otherwise the ldap_mod_replace will be used for attributes
     *
     * @param bool $dn
     * @param array $data
     * @param bool $strict
     * @return bool
     */
    public function update($dn = false, $data = [], $strict = false)
    {
        if (!$dn || !is_array($data)) {
            $this->setError("Input values empty");

            return false;
        }

        foreach ($data as $k => $v) {
            if (!isset($this->_schema_attribs[$k])) {

                if ($strict) {
                    $this->setError("Attribute {{$k}} does not exist and strict mode is active");

                    return false;
                }

                unset($data[$k]);
            }
        }

        if (isset($data['objectClass']) || $data['objectclass']) {
            if (!@ldap_modify($this->_connection, $dn, $data)) {
                $this->setError();

                return false;
            }
        } else {
            if (!@ldap_mod_replace($this->_connection, $dn, $data)) {
                $this->setError();

                return false;
            }
        }

        return $dn;
    }

    /**
     * List the records in LDAP dn path
     *
     * @param string $dn Ldap record path
     * @param array $filter Search params
     * @param array $fields
     * @return array
     */
    public function listDn($dn, $filter = [], $fields = [])
    {
        $this->_dn = $dn;
        $this->_query_builder($filter);
        $this->_field_builder($fields);

        return $this->find('all', [], $dn);

        /*if (!$search = @ldap_search($this->_connection, $this->_dn, $this->_query['conditions'], $th)) {
            $this->setError();

            return false;
        }

        $results = ldap_get_entries($this->_connection, $search);

        if (!isset($results) || $results['count'] == 0) {
            return false;
        }

        $out = [];
        foreach ($results as $k => $res) {
            if ($k == 'count') {
                continue;
            }
            $out[] = $this->clearCounts($res);
        }

        return $out;*/
    }

    /**
     * Delete LDAP Record by dn
     *
     * @param string $dn path to record to delete
     * @return bool
     */
    public function delete($dn)
    {
        if (!@ldap_delete($this->_connection, $dn)) {
            $this->setError();

            return false;
        }

        return true;
    }


    /**
     * Build DN
     *
     * @param array $params
     * @param string $base_dn
     * @return string
     */
    public function dnBuilder($params = [], $base_dn = '')
    {
        if (is_string($params)) {
            return $params . ',' . $base_dn;
        }

        $pre = '';
        foreach ($params as $k => $v) {
            $pre .= "{$k}={$v},";
        }

        return $pre . $base_dn;
    }


    /**
     * Select which LDAP attributes to return
     *
     * @param array|string $fields
     * @return $this
     */
    public function select($fields = [])
    {
        if (!is_array($fields)) {
            $fields = array_map('trim', explode(",", $fields));
        }

        $this->_query['fields'] = $fields;

        return $this;
    }


    /**
     * @param string $dn
     * @return \LdapOrm\LdapOrm
     */
    public function from($dn = '')
    {
        $this->_query['dn'] = $dn;

        return $this;
    }


    /**
     * @param array $conditions
     * @return $this
     */
    public function where($conditions = [])
    {
        $this->_query['conditions'] = $conditions;

        return $this;
    }


    /**
     * @param bool $lim
     * @return $this
     */
    public function limit($lim = false)
    {
        $this->_query['limit'] = $lim;

        return $this;
    }


    /**
     * @param bool $order
     * @return $this
     */
    public function order($order = false)
    {
        $this->_query['order'] = $order;

        return $this;
    }


    /**
     * @param $hasMany
     * @return $this
     */
    public function hasMany($hasMany)
    {
        $this->_query['hasMany'] = $hasMany;

        return $this;
    }


    /**
     * @return mixed
     */
    public function getResults()
    {
        $results = $this->find('all', [], $this->_query['dn']);

        return $results;
    }

    /**
     * @return bool
     */
    public function free_memory()
    {
        return ldap_free_result($this->_connection);
    }
}