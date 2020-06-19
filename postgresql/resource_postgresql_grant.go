package postgresql

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	// Use Postgres as SQL driver
	"github.com/lib/pq"
)

func resourcePostgreSQLGrant() *schema.Resource {
	return &schema.Resource{
		Create: resourcePostgreSQLGrantCreate,
		// As create revokes and grants we can use it to update too
		Read:   resourcePostgreSQLGrantRead,
		Delete: resourcePostgreSQLGrantDelete,

		Schema: map[string]*schema.Schema{
			"role": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role to grant privileges on",
			},
			"database": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The database to grant privileges on for this role",
			},
		},
	}
}

func resourcePostgreSQLGrantRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)

	if !client.featureSupported(featurePrivileges) {
		return fmt.Errorf(
			"postgresql_grant resource is not supported for this Postgres version (%s)",
			client.version,
		)
	}

	client.catalogLock.RLock()
	defer client.catalogLock.RUnlock()

	exists, err := checkRoleDBSchemaExists(client, d)
	if err != nil {
		return err
	}
	if !exists {
		d.SetId("")
		return nil
	}
	d.SetId(generateGrantID(d))

	txn, err := startTransaction(client, d.Get("database").(string))
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	return readDatabaseRolePrivileges(txn, d)
}

func resourcePostgreSQLGrantCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)

	if !client.featureSupported(featurePrivileges) {
		return fmt.Errorf(
			"postgresql_grant resource is not supported for this Postgres version (%s)",
			client.version,
		)
	}

	database := d.Get("database").(string)

	client.catalogLock.Lock()
	defer client.catalogLock.Unlock()

	txn, err := startTransaction(client, database)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	// Revoke all privileges before granting otherwise reducing privileges will not work.
	// We just have to revoke them in the same transaction so the role will not lost its
	// privileges between the revoke and grant statements.
	if err = revokeRolePrivileges(txn, d); err != nil {
		return err
	}

	if err = grantRolePrivileges(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errwrap.Wrapf("could not commit transaction: {{err}}", err)
	}

	d.SetId(generateGrantID(d))

	txn, err = startTransaction(client, database)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	return readDatabaseRolePrivileges(txn, d)
}

func resourcePostgreSQLGrantDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)

	if !client.featureSupported(featurePrivileges) {
		return fmt.Errorf(
			"postgresql_grant resource is not supported for this Postgres version (%s)",
			client.version,
		)
	}

	client.catalogLock.Lock()
	defer client.catalogLock.Unlock()

	txn, err := startTransaction(client, d.Get("database").(string))
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	if err = revokeRolePrivileges(txn, d); err != nil {
		return err
	}

	if err = txn.Commit(); err != nil {
		return errwrap.Wrapf("could not commit transaction: {{err}}", err)
	}

	return nil
}

func readDatabaseRolePrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	query := `
SELECT privilege_type
FROM information_schema.schema_privileges
WHERE grantee=$1
AND table_schema='public';
`

	privileges := []string{}
	rows, err := txn.Query(query, d.Get("role"))
	if err != nil {
		return errwrap.Wrapf("could not read database privileges: {{err}}", err)
	}

	for rows.Next() {
		var privilegeType string
		if err := rows.Scan(&privilegeType); err != nil {
			return errwrap.Wrapf("could not scan database privilege: {{err}}", err)
		}
		privileges = append(privileges, privilegeType)
	}

	d.Set("privileges", privileges)
	return nil
}

func createGrantQuery(d *schema.ResourceData, privileges []string) string {
	var query string

	query = fmt.Sprintf(
		"GRANT %s ON DATABASE %s TO %s",
		strings.Join(privileges, ","),
		pq.QuoteIdentifier(d.Get("database").(string)),
		pq.QuoteIdentifier(d.Get("role").(string)),
	)

	return query
}

func createRevokeQuery(d *schema.ResourceData) string {
	var query string

	query = fmt.Sprintf(
		"REVOKE ALL ON DATABASE %s FROM %s",
		pq.QuoteIdentifier(d.Get("database").(string)),
		pq.QuoteIdentifier(d.Get("role").(string)),
	)

	return query
}

func grantRolePrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	query := createGrantQuery(d, []string{"ALL"})

	_, err := txn.Exec(query)
	return err
}

func revokeRolePrivileges(txn *sql.Tx, d *schema.ResourceData) error {
	query := createRevokeQuery(d)
	if _, err := txn.Exec(query); err != nil {
		return errwrap.Wrapf("could not execute revoke query: {{err}}", err)
	}
	return nil
}

func checkRoleDBSchemaExists(client *Client, d *schema.ResourceData) (bool, error) {
	txn, err := startTransaction(client, "")
	if err != nil {
		return false, err
	}
	defer deferredRollback(txn)

	// Check the role exists
	role := d.Get("role").(string)
	exists, err := roleExists(txn, role)
	if err != nil {
		return false, err
	}
	if !exists {
		log.Printf("[DEBUG] role %s does not exists", role)
		return false, nil
	}

	// Check the database exists
	database := d.Get("database").(string)
	exists, err = dbExists(txn, database)
	if err != nil {
		return false, err
	}
	if !exists {
		log.Printf("[DEBUG] database %s does not exists", database)
		return false, nil
	}

	return true, nil
}

func generateGrantID(d *schema.ResourceData) string {
	parts := []string{d.Get("role").(string), d.Get("database").(string)}

	parts = append(parts, "database")

	return strings.Join(parts, "_")
}
