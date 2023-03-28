package main

import (
	"io"
	"os"

	"github.com/m-mizutani/goerr"
	"github.com/urfave/cli/v2"
	"go.etcd.io/bbolt"
)

type config struct {
	dbPath string
	db     *bbolt.DB
	out    io.Writer
}

func Run(argv []string) error {
	var cfg config
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "trivy-db-path",
				Aliases:     []string{"d"},
				EnvVars:     []string{"TRIVY_DB_PATH"},
				Destination: &cfg.dbPath,
				Required:    true,
			},
		},
		Before: func(c *cli.Context) error {
			db, err := bbolt.Open(cfg.dbPath, 0600, &bbolt.Options{ReadOnly: true})
			if err != nil {
				return goerr.Wrap(err)
			}
			cfg.db = db
			cfg.out = os.Stdout
			return nil
		},
		After: func(c *cli.Context) error {
			if cfg.db != nil {
				if err := cfg.db.Close(); err != nil {
					return goerr.Wrap(err)
				}
			}
			return nil
		},
		Commands: []*cli.Command{
			newVulnerabilityCommand(&cfg),
			newAdvisoryCommand(&cfg),
			newTrivyCommand(&cfg),
			newDumpCommand(&cfg),
		},
	}

	if err := app.Run(argv); err != nil {
		return err
	}
	return nil
}
