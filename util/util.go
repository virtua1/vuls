/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package util

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/future-architect/vuls/config"
	"golang.org/x/xerrors"
)

var cacheDir string

// DefaultCacheDir :
func DefaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "vuls")
}

// SetCacheDir :
func SetCacheDir(dir string) {
	cacheDir = dir
}

// CacheDir :
func CacheDir() string {
	return cacheDir
}

// GenWorkers generates goroutine
// http://qiita.com/na-o-ys/items/65373132b1c5bc973cca
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			defer func() {
				if p := recover(); p != nil {
					log := NewCustomLogger(config.ServerInfo{})
					log.Errorf("run time panic: %v", p)
				}
			}()
			for f := range tasks {
				f()
			}
		}()
	}
	return tasks
}

// AppendIfMissing append to the slice if missing
func AppendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}

// URLPathJoin make URL
func URLPathJoin(baseURL string, paths ...string) (string, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	trimedPaths := []string{}
	for _, path := range paths {
		trimed := strings.Trim(path, " /")
		if len(trimed) != 0 {
			trimedPaths = append(trimedPaths, trimed)
		}
	}
	var url *url.URL
	url, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	url.Path += "/" + strings.Join(trimedPaths, "/")
	return url.String(), nil
}

// URLPathParamJoin make URL
func URLPathParamJoin(baseURL string, paths []string, params map[string]string) (string, error) {
	urlPath, err := URLPathJoin(baseURL, paths...)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(urlPath)
	if err != nil {
		return "", err
	}

	parameters := url.Values{}
	for key := range params {
		parameters.Add(key, params[key])
	}
	u.RawQuery = parameters.Encode()
	return u.String(), nil
}

// IP returns scanner network ip addresses
func IP() (ipv4Addrs []string, ipv6Addrs []string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// only global unicast address
			if !ip.IsGlobalUnicast() {
				continue
			}

			if ok := ip.To4(); ok != nil {
				ipv4Addrs = append(ipv4Addrs, ip.String())
			} else {
				ipv6Addrs = append(ipv6Addrs, ip.String())
			}
		}
	}
	return ipv4Addrs, ipv6Addrs, nil
}

// ProxyEnv returns shell environment variables to set proxy
func ProxyEnv() string {
	httpProxyEnv := ""
	keys := []string{
		"http_proxy",
		"https_proxy",
		"HTTP_PROXY",
		"HTTPS_PROXY",
	}
	for _, key := range keys {
		httpProxyEnv += fmt.Sprintf(
			` %s="%s"`, key, config.Conf.HTTPProxy)
	}
	return httpProxyEnv
}

// PrependProxyEnv prepends proxy environment variable
func PrependProxyEnv(cmd string) string {
	if len(config.Conf.HTTPProxy) == 0 {
		return cmd
	}
	return fmt.Sprintf("%s %s", ProxyEnv(), cmd)
}

//  func unixtime(s string) (time.Time, error) {
//      i, err := strconv.ParseInt(s, 10, 64)
//      if err != nil {
//          return time.Time{}, err
//      }
//      return time.Unix(i, 0), nil
//  }

// Truncate truncates string to the length
func Truncate(str string, length int) string {
	if length < 0 {
		return str
	}
	if length <= len(str) {
		return str[:length]
	}
	return str
}

// Distinct a slice
func Distinct(ss []string) (distincted []string) {
	m := map[string]bool{}
	for _, s := range ss {
		if _, found := m[s]; !found {
			m[s] = true
			distincted = append(distincted, s)
		}
	}
	return
}

// FileWalk :
func FileWalk(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return xerrors.Errorf("error in filepath rel: %w", err)
		}

		if _, ok := targetFiles[rel]; !ok {
			return nil
		}

		if info.Size() == 0 {
			log.Printf("invalid size: %s", path)
			return nil
		}

		f, err := os.Open(path)
		defer f.Close()
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in file walk: %w", err)
	}
	return nil
}

// IsCommandAvailable :
func IsCommandAvailable(name string) bool {
	cmd := exec.Command(name, "--help")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// Exists :
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// StringInSlice :
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Exec :
func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Println(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

// FilterTargets :
func FilterTargets(prefixPath string, targets map[string]struct{}) (map[string]struct{}, error) {
	filtered := map[string]struct{}{}
	for filename := range targets {
		if strings.HasPrefix(filename, prefixPath) {
			rel, err := filepath.Rel(prefixPath, filename)
			if err != nil {
				return nil, xerrors.Errorf("error in filepath rel: %w", err)
			}
			if strings.HasPrefix(rel, "../") {
				continue
			}
			filtered[rel] = struct{}{}
		}
	}
	return filtered, nil
}
