package main

import (
	"encoding/json"

	"github.com/m-mizutani/goerr"
	"github.com/urfave/cli/v2"
	"go.etcd.io/bbolt"
)

func newDumpCommand(cfg *config) *cli.Command {
	return &cli.Command{
		Name:      "dump",
		Aliases:   []string{"d"},
		Usage:     "Dump advisory",
		ArgsUsage: "[source [package]] ",
		Action: func(c *cli.Context) error {
			switch c.Args().Len() {
			case 0:
				return showAdvisorySources(cfg)
			case 1:
				return showAdvisoryAllPackageInfo(cfg, c.Args().Get(0))
			}
			return nil
		},
	}
}

type vulnInfo struct {
	PkgName string
	VulnID  string
	Data    any
}

func showAdvisoryAllPackageInfo(cfg *config, source string) error {
	out := json.NewEncoder(cfg.out)

	view := func(tx *bbolt.Tx) error {
		vulnBucket := tx.Bucket([]byte(vulnerabilityBucket))
		if vulnBucket == nil {
			return goerr.Wrap(errInvalidDatabase, "vulnerability bucket is not found")
		}

		srcBucket := tx.Bucket([]byte(source))
		if srcBucket == nil {
			return goerr.Wrap(errResourceNotFound, "No such source bucket").With("source", source)
		}

		if err := srcBucket.ForEach(func(pkgName, v []byte) error {
			pkgBucket := srcBucket.Bucket(pkgName)
			if pkgBucket == nil {
				return goerr.Wrap(errResourceNotFound, "No such package bucket").With("pkgName", pkgBucket)
			}

			if err := pkgBucket.ForEach(func(vulnID, v []byte) error {
				vuln := vulnBucket.Get(vulnID)
				if vuln == nil {
					return goerr.Wrap(errResourceNotFound, "No such vulnerability").With("vulnID", string(vulnID))
				}

				var vulnData any
				if err := json.Unmarshal(vuln, &vulnData); err != nil {
					return goerr.Wrap(err)
				}

				info := vulnInfo{
					PkgName: string(pkgName),
					VulnID:  string(vulnID),
					Data:    vulnData,
				}
				if err := out.Encode(info); err != nil {
					return goerr.Wrap(err, "encode vulnInfo to output stream")
				}

				return nil
			}); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return err
		}

		return nil
	}

	if err := cfg.db.View(view); err != nil {
		return err
	}

	return nil
}
