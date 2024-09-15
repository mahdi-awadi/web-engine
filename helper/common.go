package helper

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
)

// GetRelativePath get relative path
func GetRelativePath(path string) string {
	pwd, _ := os.Getwd()
	return filepath.Join(pwd, path)
}

// RuntimePath returns path in runtime directory
func RuntimePath(path ...string) string {
	var pathSlice []string
	pathSlice = append(pathSlice, "runtime")
	pathSlice = append(pathSlice, path...)
	filePath := filepath.Join(pathSlice...)
	return GetRelativePath(filePath)
}

// ReadFile read file form root directory.
func ReadFile(path string) (content []byte, err error) {
	content, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("can not read file in path: " + path)
	}

	err = nil
	return
}

// IsInstanceOf check object instance
func IsInstanceOf(objectPtr, typePtr interface{}) bool {
	return reflect.TypeOf(objectPtr) == reflect.TypeOf(typePtr)
}

// JsonString convert struct to json string
func JsonString(s interface{}) (error, string) {
	b, err := json.Marshal(s)
	if err != nil {
		return err, ""
	}
	return nil, string(b)
}

// IsStringInSlice determines is in list.
func IsStringInSlice(str string, list []string) bool {
	for _, b := range list {
		if b == str {
			return true
		}
	}
	return false
}
