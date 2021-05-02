package main

import (
	"fmt"

	"github.com/m-mizutani/goerr"
	"github.com/urfave/cli/v2"
	"go.etcd.io/bbolt"
)

const (
	trivyBucket = "trivy"
)

func newAdvisoryCommand(cfg *config) *cli.Command {
	return &cli.Command{
		Name:      "advisory",
		Aliases:   []string{"adv"},
		Usage:     "Show advisory",
		ArgsUsage: "[source [package]] ",
		Action: func(c *cli.Context) error {
			switch c.Args().Len() {
			case 0:
				return showAdvisorySources(cfg)
			case 1:
				return showAdvisoryPackages(cfg, c.Args().Get(0))
			case 2:
				return showAdvisoryPackageInfo(cfg, c.Args().Get(0), c.Args().Get(1))
			}
			return nil
		},
	}
}

func contains(strset []string, str string) bool {
	for i := range strset {
		if strset[i] == str {
			return true
		}
	}
	return false
}

func showAdvisorySources(cfg *config) error {
	metaBuckets := []string{vulnerabilityBucket, trivyBucket}
	view := func(tx *bbolt.Tx) error {
		tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			if contains(metaBuckets, string(name)) {
				return nil
			}
			fmt.Fprintf(cfg.out, "%s\n", string(name))
			return nil
		})
		return nil
	}

	if err := cfg.db.View(view); err != nil {
		return err
	}

	return nil
}

func showAdvisoryPackages(cfg *config, source string) error {
	view := func(tx *bbolt.Tx) error {
		srcBucket := tx.Bucket([]byte(source))
		if srcBucket == nil {
			return goerr.Wrap(errResourceNotFound, "No such source bucket").With("source", source)
		}

		srcBucket.ForEach(func(k, v []byte) error {
			fmt.Fprintf(cfg.out, "%s\n", string(k))
			return nil
		})
		return nil
	}

	if err := cfg.db.View(view); err != nil {
		return err
	}

	return nil
}

func showAdvisoryPackageInfo(cfg *config, source string, pkgName string) error {
	view := func(tx *bbolt.Tx) error {
		srcBucket := tx.Bucket([]byte(source))
		if srcBucket == nil {
			return goerr.Wrap(errResourceNotFound, "No such source bucket").With("source", source)
		}

		pkgBucket := srcBucket.Bucket([]byte(pkgName))
		if pkgBucket == nil {
			return goerr.Wrap(errResourceNotFound, "No such package bucket").With("pkgName", pkgName)
		}

		pkgBucket.ForEach(func(k, v []byte) error {
			fmt.Fprintf(cfg.out, "%s: %s\n", string(k), string(v))
			return nil
		})

		return nil
	}

	if err := cfg.db.View(view); err != nil {
		return err
	}

	return nil
}
