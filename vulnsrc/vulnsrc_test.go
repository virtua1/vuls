package vulnsrc

import (
	"path/filepath"
	"testing"

	"github.com/future-architect/vuls/db"
	"github.com/future-architect/vuls/git"
	"github.com/future-architect/vuls/util"
	"github.com/future-architect/vuls/vulnsrc/vulnerability"
)

func BenchmarkUpdate(b *testing.B) {
	util.Quiet = true
	if err := db.Init(); err != nil {
		b.Fatal(err)
	}
	dir := filepath.Join(util.CacheDir(), "vuln-list")
	if _, err := git.CloneOrPull(repoURL, dir); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	b.Run("NVD", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := db.SetVersion(""); err != nil {
				b.Fatal(err)
			}
			if err := Update([]string{vulnerability.Nvd}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
