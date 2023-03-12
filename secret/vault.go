package secret

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/NaNameUz3r/secret_store/encrypt"
)

type Vault struct {
	filePath  string
	encodeKey string
	mutex     sync.Mutex
	keyValues map[string]string
}

func FileVault(key, filePath string) *Vault {
	return &Vault{
		encodeKey: key,
		filePath:  filePath,
		keyValues: make(map[string]string),
	}
}

func (v *Vault) fetch() error {
	file, err := os.Open(v.filePath)
	if err != nil {
		v.keyValues = make(map[string]string)
		return nil
	}
	defer file.Close()

	reader, err := encrypt.DecryptReader(v.encodeKey, file)
	if err != nil {
		return err
	}

	return v.readKeyVals(reader)
}

func (v *Vault) readKeyVals(r io.Reader) error {
	dec := json.NewDecoder(r)
	return dec.Decode(&v.keyValues)
}

func (v *Vault) save() error {
	file, err := os.OpenFile(v.filePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer file.Close()
	writer, err := encrypt.EncryptWriter(v.encodeKey, file)
	if err != nil {
		return err
	}

	return v.writeKeyVals(writer)
}

func (v *Vault) writeKeyVals(w io.Writer) error {
	enc := json.NewEncoder(w)
	return enc.Encode(v.keyValues)
}

func (v *Vault) Get(key string) (string, error) {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	err := v.fetch()
	if err != nil {
		return "", err
	}

	value, ok := v.keyValues[key]
	if !ok {
		return "", errors.New("secret: value for key not found")
	}
	return value, nil
}

func (v *Vault) Set(key, value string) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	err := v.fetch()
	if err != nil {
		return err
	}

	v.keyValues[key] = value
	err = v.save()

	if err != nil {
		return err
	}
	return nil
}
