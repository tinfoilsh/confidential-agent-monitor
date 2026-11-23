// Package migrate upgrades what older versions of the Perimeter stored.
package migrate

// Document upgrades a stored document of any supported version to the current one.
func Document(plain []byte) ([]byte, *Migration, error) {
	plain, err := upgradeV2(plain)
	if err == nil {
		plain, err = upgradeV3(plain)
	}
	if err != nil {
		return nil, nil, err
	}
	return upgradeV4(plain)
}
