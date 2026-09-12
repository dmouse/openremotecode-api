package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const connectionTimeout = 5 * time.Second

func Open(dsn string) (*gorm.DB, *sql.DB, error) {
	database, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
		TranslateError:         true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("obtain PostgreSQL pool: %w", err)
	}
	sqlDatabase.SetMaxIdleConns(5)
	sqlDatabase.SetMaxOpenConns(20)
	sqlDatabase.SetConnMaxIdleTime(5 * time.Minute)
	sqlDatabase.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()
	if err := sqlDatabase.PingContext(ctx); err != nil {
		_ = sqlDatabase.Close()
		return nil, nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return database, sqlDatabase, nil
}
