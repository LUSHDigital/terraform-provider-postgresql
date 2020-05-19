package postgresql

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/lib/pq"
)

const (
	roleCreateRoleAttr       = "create_role"
	roleLoginAttr            = "login"
	roleNameAttr             = "name"
	rolePasswordAttr         = "password"
	roleSkipDropRoleAttr     = "skip_drop_role"
	roleValidUntilAttr       = "valid_until"
	roleRolesAttr            = "roles"
	roleStatementTimeoutAttr = "statement_timeout"
)

func resourcePostgreSQLRole() *schema.Resource {
	return &schema.Resource{
		Create: resourcePostgreSQLRoleCreate,
		Read:   resourcePostgreSQLRoleRead,
		Update: resourcePostgreSQLRoleUpdate,
		Delete: resourcePostgreSQLRoleDelete,
		Exists: resourcePostgreSQLRoleExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			roleNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The name of the role",
			},
			rolePasswordAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Sets the role's password",
			},
			roleRolesAttr: {
				Type:        schema.TypeSet,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Set:         schema.HashString,
				MinItems:    0,
				Description: "Role(s) to grant to this new role",
			},
			roleValidUntilAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "infinity",
				Description: "Sets a date and time after which the role's password is no longer valid",
			},
			roleCreateRoleAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether this role will be permitted to create new roles",
			},
			roleLoginAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Determine whether a role is allowed to log in",
			},
			roleSkipDropRoleAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Skip actually running the DROP ROLE command when removing a ROLE from PostgreSQL",
			},
			roleStatementTimeoutAttr: {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Abort any statement that takes more than the specified number of milliseconds",
				ValidateFunc: validation.IntAtLeast(0),
			},
		},
	}
}

func resourcePostgreSQLRoleCreate(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	txn, err := c.DB().Begin()
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	stringOpts := []struct {
		hclKey string
		sqlKey string
	}{
		{rolePasswordAttr, "PASSWORD"},
		{roleValidUntilAttr, "VALID UNTIL"},
	}

	type boolOptType struct {
		hclKey        string
		sqlKeyEnable  string
		sqlKeyDisable string
	}
	boolOpts := []boolOptType{
		{roleCreateRoleAttr, "CREATEROLE", "NOCREATEROLE"},
		{roleLoginAttr, "LOGIN", "NOLOGIN"},
		// roleEncryptedPassAttr is used only when rolePasswordAttr is set.
		// {roleEncryptedPassAttr, "ENCRYPTED", "UNENCRYPTED"},
	}

	createOpts := make([]string, 0, len(stringOpts)+len(boolOpts))

	for _, opt := range stringOpts {
		v, ok := d.GetOk(opt.hclKey)
		if !ok {
			continue
		}

		val := v.(string)
		if val != "" {
			switch {
			case opt.hclKey == rolePasswordAttr:
				if strings.ToUpper(v.(string)) == "NULL" {
					createOpts = append(createOpts, "PASSWORD NULL")
				} else {
					createOpts = append(createOpts, fmt.Sprintf("%s '%s'", opt.sqlKey, pqQuoteLiteral(val)))
				}
			case opt.hclKey == roleValidUntilAttr:
				switch {
				case v.(string) == "", strings.ToLower(v.(string)) == "infinity":
					createOpts = append(createOpts, fmt.Sprintf("%s '%s'", opt.sqlKey, "infinity"))
				default:
					createOpts = append(createOpts, fmt.Sprintf("%s '%s'", opt.sqlKey, pqQuoteLiteral(val)))
				}
			default:
				createOpts = append(createOpts, fmt.Sprintf("%s %s", opt.sqlKey, pq.QuoteIdentifier(val)))
			}
		}
	}

	for _, opt := range boolOpts {
		val := d.Get(opt.hclKey).(bool)
		valStr := opt.sqlKeyDisable
		if val {
			valStr = opt.sqlKeyEnable
		}
		createOpts = append(createOpts, valStr)
	}

	roleName := d.Get(roleNameAttr).(string)
	createStr := strings.Join(createOpts, " ")
	if len(createOpts) > 0 {
		if c.featureSupported(featureCreateRoleWith) {
			createStr = " WITH " + createStr
		} else {
			// NOTE(seanc@): Work around ParAccel/AWS RedShift's ancient fork of PostgreSQL
			createStr = " " + createStr
		}
	}

	sql := fmt.Sprintf("CREATE ROLE %s%s", pq.QuoteIdentifier(roleName), createStr)
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf(fmt.Sprintf("error creating role %s: {{err}}", roleName), err)
	}

	if err = grantRoles(txn, d); err != nil {
		return err
	}

	if err = setStatementTimeout(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errwrap.Wrapf("could not commit transaction: {{err}}", err)
	}

	d.SetId(roleName)

	return resourcePostgreSQLRoleReadImpl(c, d)
}

func resourcePostgreSQLRoleDelete(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	txn, err := c.DB().Begin()
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	roleName := d.Get(roleNameAttr).(string)

	queries := make([]string, 0, 3)

	if !d.Get(roleSkipDropRoleAttr).(bool) {
		queries = append(queries, fmt.Sprintf("DROP ROLE %s", pq.QuoteIdentifier(roleName)))
	}

	if len(queries) > 0 {
		for _, query := range queries {
			if _, err := txn.Exec(query); err != nil {
				return errwrap.Wrapf("Error deleting role: {{err}}", err)
			}
		}

		if err := txn.Commit(); err != nil {
			return errwrap.Wrapf("Error committing schema: {{err}}", err)
		}
	}

	d.SetId("")

	return nil
}

func resourcePostgreSQLRoleExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	c := meta.(*Client)
	c.catalogLock.RLock()
	defer c.catalogLock.RUnlock()

	var roleName string
	err := c.DB().QueryRow("SELECT rolname FROM pg_catalog.pg_roles WHERE rolname=$1", d.Id()).Scan(&roleName)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func resourcePostgreSQLRoleRead(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.RLock()
	defer c.catalogLock.RUnlock()

	return resourcePostgreSQLRoleReadImpl(c, d)
}

func resourcePostgreSQLRoleReadImpl(c *Client, d *schema.ResourceData) error {
	var roleCreateRole, roleCanLogin bool
	var roleName, roleValidUntil string
	var roleRoles, roleConfig pq.ByteaArray

	roleID := d.Id()

	columns := []string{
		"rolname",
		"rolcreaterole",
		"rolcanlogin",
		`COALESCE(rolvaliduntil::TEXT, 'infinity')`,
		"rolconfig",
	}

	values := []interface{}{
		&roleRoles,
		&roleName,
		&roleCreateRole,
		&roleCanLogin,
		&roleValidUntil,
		&roleConfig,
	}

	roleSQL := fmt.Sprintf(`SELECT ARRAY(
			SELECT pg_get_userbyid(roleid) FROM pg_catalog.pg_auth_members members WHERE member = pg_roles.oid
		), %s
		FROM pg_catalog.pg_roles WHERE rolname=$1`,
		// select columns
		strings.Join(columns, ", "),
	)
	err := c.DB().QueryRow(roleSQL, roleID).Scan(values...)

	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL ROLE (%s) not found", roleID)
		d.SetId("")
		return nil
	case err != nil:
		return errwrap.Wrapf("Error reading ROLE: {{err}}", err)
	}

	d.Set(roleNameAttr, roleName)
	d.Set(roleCreateRoleAttr, roleCreateRole)
	d.Set(roleLoginAttr, roleCanLogin)
	d.Set(roleSkipDropRoleAttr, d.Get(roleSkipDropRoleAttr).(bool))
	d.Set(roleValidUntilAttr, roleValidUntil)
	d.Set(roleRolesAttr, pgArrayToSet(roleRoles))

	statementTimeout, err := readStatementTimeout(roleConfig)
	if err != nil {
		return err
	}

	d.Set(roleStatementTimeoutAttr, statementTimeout)

	d.SetId(roleName)

	password, err := readRolePassword(c, d, roleCanLogin)
	if err != nil {
		return err
	}

	d.Set(rolePasswordAttr, password)
	return nil
}

// readStatementTimeout searches for a statement_timeout entry in the rolconfig array.
// In case no such value is present, it returns nil.
func readStatementTimeout(roleConfig pq.ByteaArray) (int, error) {
	for _, v := range roleConfig {
		config := string(v)
		if strings.HasPrefix(config, roleStatementTimeoutAttr) {
			var result = strings.Split(strings.TrimPrefix(config, roleStatementTimeoutAttr+"="), ", ")
			res, err := strconv.Atoi(result[0])
			if err != nil {
				return -1, errwrap.Wrapf("Error reading statement_timeout: {{err}}", err)
			}
			return res, nil
		}
	}
	return 0, nil
}

// readRolePassword reads password either from Postgres if admin user is a superuser
// or only from Terraform state.
func readRolePassword(c *Client, d *schema.ResourceData, roleCanLogin bool) (string, error) {
	statePassword := d.Get(rolePasswordAttr).(string)

	// Role which cannot login does not have password in pg_shadow.
	// Also, if user specifies that admin is not a superuser we don't try to read pg_shadow
	// (only superuser can read pg_shadow)
	if !roleCanLogin || !c.config.Superuser {
		return statePassword, nil
	}

	// Otherwise we check if connected user is really a superuser
	// (in order to warn user instead of having a permission denied error)
	superuser, err := c.isSuperuser()
	if err != nil {
		return "", err
	}
	if !superuser {
		return "", fmt.Errorf(
			"could not read role password from Postgres as "+
				"connected user %s is not a SUPERUSER. "+
				"You can set `superuser = false` in the provider configuration "+
				"so it will not try to read the password from Postgres",
			c.config.getDatabaseUsername(),
		)
	}

	var rolePassword string
	err = c.DB().QueryRow("SELECT COALESCE(passwd, '') FROM pg_catalog.pg_shadow AS s WHERE s.usename = $1", d.Id()).Scan(&rolePassword)
	switch {
	case err == sql.ErrNoRows:
		// They don't have a password
		return "", nil
	case err != nil:
		return "", errwrap.Wrapf("Error reading role: {{err}}", err)
	}
	// If the password isn't already in md5 format, but hashing the input
	// matches the password in the database for the user, they are the same
	if statePassword != "" && !strings.HasPrefix(statePassword, "md5") && !strings.HasPrefix(statePassword, "SCRAM-SHA-256") {
		if strings.HasPrefix(rolePassword, "md5") {
			hasher := md5.New()
			hasher.Write([]byte(statePassword + d.Id()))
			hashedPassword := "md5" + hex.EncodeToString(hasher.Sum(nil))

			if hashedPassword == rolePassword {
				// The passwords are actually the same
				// make Terraform think they are the same
				return statePassword, nil
			}
		}
		if strings.HasPrefix(rolePassword, "SCRAM-SHA-256") {
			return statePassword, nil
			// TODO : implement scram-sha-256 challenge request to the server
		}
	}
	return rolePassword, nil
}

func resourcePostgreSQLRoleUpdate(d *schema.ResourceData, meta interface{}) error {
	c := meta.(*Client)
	c.catalogLock.Lock()
	defer c.catalogLock.Unlock()

	txn, err := c.DB().Begin()
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	if err := setRoleName(txn, d); err != nil {
		return err
	}

	if err := setRolePassword(txn, d); err != nil {
		return err
	}

	if err := setRoleCreateRole(txn, d); err != nil {
		return err
	}

	if err := setRoleLogin(txn, d); err != nil {
		return err
	}

	if err := setRoleValidUntil(txn, d); err != nil {
		return err
	}

	// applying roles: let's revoke all / grant the right ones
	if err = revokeRoles(txn, d); err != nil {
		return err
	}

	if err = grantRoles(txn, d); err != nil {
		return err
	}

	if err = setStatementTimeout(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errwrap.Wrapf("could not commit transaction: {{err}}", err)
	}

	return resourcePostgreSQLRoleReadImpl(c, d)
}

func setRoleName(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleNameAttr) {
		return nil
	}

	oraw, nraw := d.GetChange(roleNameAttr)
	o := oraw.(string)
	n := nraw.(string)
	if n == "" {
		return errors.New("Error setting role name to an empty string")
	}

	sql := fmt.Sprintf("ALTER ROLE %s RENAME TO %s", pq.QuoteIdentifier(o), pq.QuoteIdentifier(n))
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating role NAME: {{err}}", err)
	}

	d.SetId(n)

	return nil
}

func setRolePassword(txn *sql.Tx, d *schema.ResourceData) error {
	// If role is renamed, password is reset (as the md5 sum is also base on the role name)
	// so we need to update it
	if !d.HasChange(rolePasswordAttr) && !d.HasChange(roleNameAttr) {
		return nil
	}

	roleName := d.Get(roleNameAttr).(string)
	password := d.Get(rolePasswordAttr).(string)

	sql := fmt.Sprintf("ALTER ROLE %s PASSWORD '%s'", pq.QuoteIdentifier(roleName), pqQuoteLiteral(password))
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating role password: {{err}}", err)
	}
	return nil
}

func setRoleCreateRole(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleCreateRoleAttr) {
		return nil
	}

	createRole := d.Get(roleCreateRoleAttr).(bool)
	tok := "NOCREATEROLE"
	if createRole {
		tok = "CREATEROLE"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating role CREATEROLE: {{err}}", err)
	}

	return nil
}

func setRoleLogin(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleLoginAttr) {
		return nil
	}

	login := d.Get(roleLoginAttr).(bool)
	tok := "NOLOGIN"
	if login {
		tok = "LOGIN"
	}
	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s WITH %s", pq.QuoteIdentifier(roleName), tok)
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating role LOGIN: {{err}}", err)
	}

	return nil
}

func setRoleValidUntil(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleValidUntilAttr) {
		return nil
	}

	validUntil := d.Get(roleValidUntilAttr).(string)
	if validUntil == "" {
		return nil
	} else if strings.ToLower(validUntil) == "infinity" {
		validUntil = "infinity"
	}

	roleName := d.Get(roleNameAttr).(string)
	sql := fmt.Sprintf("ALTER ROLE %s VALID UNTIL '%s'", pq.QuoteIdentifier(roleName), pqQuoteLiteral(validUntil))
	if _, err := txn.Exec(sql); err != nil {
		return errwrap.Wrapf("Error updating role VALID UNTIL: {{err}}", err)
	}

	return nil
}

func revokeRoles(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get(roleNameAttr).(string)

	query := `SELECT pg_get_userbyid(roleid)
		FROM pg_catalog.pg_auth_members members
		JOIN pg_catalog.pg_roles ON members.member = pg_roles.oid
		WHERE rolname = $1`

	rows, err := txn.Query(query, role)
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("could not get roles list for role %s: {{err}}", role), err)
	}
	defer rows.Close()

	grantedRoles := []string{}
	for rows.Next() {
		var grantedRole string

		if err = rows.Scan(&grantedRole); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not scan role name for role %s: {{err}}", role), err)
		}
		// We cannot revoke directly here as it shares the same cursor (with Tx)
		// and rows.Next seems to retrieve result row by row.
		// see: https://github.com/lib/pq/issues/81
		grantedRoles = append(grantedRoles, grantedRole)
	}

	for _, grantedRole := range grantedRoles {
		query = fmt.Sprintf("REVOKE %s FROM %s", pq.QuoteIdentifier(grantedRole), pq.QuoteIdentifier(role))

		log.Printf("[DEBUG] revoking role %s from %s", grantedRole, role)
		if _, err := txn.Exec(query); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not revoke role %s from %s: {{err}}", string(grantedRole), role), err)
		}
	}

	return nil
}

func grantRoles(txn *sql.Tx, d *schema.ResourceData) error {
	role := d.Get(roleNameAttr).(string)

	for _, grantingRole := range d.Get("roles").(*schema.Set).List() {
		query := fmt.Sprintf(
			"GRANT %s TO %s", pq.QuoteIdentifier(grantingRole.(string)), pq.QuoteIdentifier(role),
		)
		if _, err := txn.Exec(query); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not grant role %s to %s: {{err}}", grantingRole, role), err)
		}
	}
	return nil
}

func setStatementTimeout(txn *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleStatementTimeoutAttr) {
		return nil
	}

	roleName := d.Get(roleNameAttr).(string)
	statementTimeout := d.Get(roleStatementTimeoutAttr).(int)
	if statementTimeout != 0 {
		sql := fmt.Sprintf(
			"ALTER ROLE %s SET statement_timeout TO %d", pq.QuoteIdentifier(roleName), statementTimeout,
		)
		if _, err := txn.Exec(sql); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not set statement_timeout %d for %s: {{err}}", statementTimeout, roleName), err)
		}
	} else {
		sql := fmt.Sprintf(
			"ALTER ROLE %s RESET statement_timeout", pq.QuoteIdentifier(roleName),
		)
		if _, err := txn.Exec(sql); err != nil {
			return errwrap.Wrapf(fmt.Sprintf("could not reset statement_timeout for %s: {{err}}", roleName), err)
		}
	}
	return nil
}
