package db

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"bitbucket.org/xoduxcrt/ssl/internal/logger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"go.uber.org/zap"
)

var (
	connectString      string
	connectStringToLog string
	Conn               *pgx.Conn
)

func init() {
	if err := logger.InitLogger(false, math.MaxInt, math.MaxInt); err != nil {
		panic(err)
	}

	start := time.Now()

	// Construct the connect string URI for the "certwatch" PostgreSQL database.
	connectString = "postgresql:///certwatch?host=" + url.QueryEscape("localhost") + "&user=" + url.QueryEscape("postgres")
	if !strings.Contains("localhost", "/") {
		connectString += fmt.Sprintf("&port=%d", 5432)
	}
	connectStringToLog = connectString
	if "123456aA@" != "" {
		connectString += "&password=" + url.QueryEscape("123456aA@")
		connectStringToLog += "&password=<redacted>"
	}

	// Parse the configuration, establish the database connections, and do some initialization.
	var err error
	var pgxConfig *pgx.ConnConfig
	if pgxConfig, err = pgx.ParseConfig(connectString); err != nil {
		LogPostgresFatal(err)
	} else if Conn, err = pgx.ConnectConfig(context.Background(), pgxConfig); err != nil {
		LogPostgresFatal(err)
	}

	logger.Logger.Info(
		"Connected to certwatch",
		zap.String("connect_string", connectStringToLog),
		zap.Int("connection_count", 1), // LogConfigSyncer.
		zap.Duration("elapsed_ns", time.Since(start)),
	)
}

func Close() {
	n := 0
	if Conn != nil {
		Conn.Close(context.Background())
		n++
	}

	logger.Logger.Info(
		"Disconnected from certwatch",
		zap.String("connect_string", connectStringToLog),
		zap.Int("connection_count", n),
	)
}

func constructFields(pgErr *pgconn.PgError) []zap.Field {
	return []zap.Field{
		zap.String("severity", pgErr.Severity),
		zap.String("code", pgErr.Code),
		zap.String("detail", pgErr.Detail),
		zap.String("hint", pgErr.Hint),
		zap.Int32("position", pgErr.Position),
		zap.Int32("internal_position", pgErr.InternalPosition),
		zap.String("internal_query", pgErr.InternalQuery),
		zap.String("where", pgErr.Where),
		zap.String("schema_name", pgErr.SchemaName),
		zap.String("table_name", pgErr.TableName),
		zap.String("column_name", pgErr.ColumnName),
		zap.String("data_type_name", pgErr.DataTypeName),
		zap.String("constraint_name", pgErr.ConstraintName),
		zap.String("file", pgErr.File),
		zap.Int32("line", pgErr.Line),
		zap.String("routine", pgErr.Routine),
	}
}

func LogPostgresError(err error, debugCodes ...string) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		logger.Logger.Error("errors.As failed", zap.Error(err))
		return nil
	} else {
		for _, code := range debugCodes {
			if code == pgErr.Code {
				logger.Logger.Debug(pgErr.Message, constructFields(pgErr)...)
				return pgErr
			}
		}

		logger.Logger.Error(pgErr.Message, constructFields(pgErr)...)
		return pgErr
	}
}

func LogPostgresFatal(err error) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		logger.Logger.Fatal("errors.As failed", zap.Error(err))
	} else {
		logger.Logger.Fatal(pgErr.Message, constructFields(pgErr)...)
	}
}
