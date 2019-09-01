package vulnlist

import (
	"github.com/future-architect/vuls/vulnsrc/vulnerability"
	"github.com/kotakanbe/go-cve-dictionary/models"
)

// GetCveDetail :
func GetCveDetail(cveID string) (cveDetail *models.CveDetail, err error) {
	cveDetail = &models.CveDetail{}
	v, err := vulnerability.Get(cveID)
	if err != nil {
		return nil, err
	}
	_ = v
	// pp.Println(v)

	cveDetail = &models.CveDetail{
		CveID:   "",
		NvdJSON: &models.NvdJSON{},
		Jvn:     &models.Jvn{},
	}
	return cveDetail, nil
}
