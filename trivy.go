package main

import (
	"fmt"

	"github.com/m-mizutani/goerr"
	"github.com/urfave/cli/v2"
	"go.etcd.io/bbolt"
)

const (
	trivyBucketName = "trivy"
)

func newTrivyCommand(cfg *config) *cli.Command {
	return &cli.Command{
		Name:  "trivy",
		Usage: "Show trivy meta data",
		Action: func(c *cli.Context) error {
			return showTrivyMetaData(cfg)
		},
	}
}

func showTrivyMetaData(cfg *config) error {
	view := func(tx *bbolt.Tx) error {
		trivyBucket := tx.Bucket([]byte(trivyBucketName))
		if trivyBucket == nil {
			return goerr.Wrap(errInvalidDatabase, "trivy bucket is not found")
		}

		metadataBucket := trivyBucket.Bucket([]byte("metadata"))
		if metadataBucket == nil {
			return goerr.Wrap(errResourceNotFound).With("target", "metadata")
		}

		fmt.Fprintf(cfg.out, "%s\n", metadataBucket.Get([]byte("data")))
		return nil
	}

	if err := cfg.db.View(view); err != nil {
		return err
	}

	return nil
}
