//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"opencode-remote/server/internal/identity"
	identitypostgres "opencode-remote/server/internal/identity/postgres"

	"gorm.io/gorm"
)

const (
	federatedSubject = "108734295610293847561"
	otherSubject     = "209845736102938475612"
)

func seedFederatedUser(
	t *testing.T,
	database *gorm.DB,
	userID string,
	email string,
	passwordHash *string,
	now time.Time,
) {
	t.Helper()
	if err := database.Create(&identitypostgres.UserModel{
		ID:              userID,
		Email:           email,
		NormalizedEmail: email,
		PasswordHash:    passwordHash,
		Status:          identity.AccountStatusActive,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
	}).Error; err != nil {
		t.Fatalf("seed user %q: %v", userID, err)
	}
}

// A federated account has no password at all. The column has to accept NULL, or the
// whole Google path fails at the first insert.
func TestFederatedAccountStoresNoPasswordHash(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	store := identitypostgres.NewStore(isolatedDatabase)
	now := time.Now().UTC().Truncate(time.Microsecond)

	err := store.WithinTransaction(context.Background(), func(transaction identity.TransactionStore) error {
		return transaction.CreateUser(context.Background(), identity.User{
			Account: identity.Account{
				ID:              "usr_federated_account_01",
				Email:           "person@example.com",
				Status:          identity.AccountStatusActive,
				EmailVerifiedAt: &now,
				CreatedAt:       now,
			},
			NormalizedEmail: "person@example.com",
			PasswordHash:    nil,
		})
	})
	if err != nil {
		t.Fatalf("create federated account: %v", err)
	}

	stored, err := store.UserByNormalizedEmail(context.Background(), "person@example.com")
	if err != nil {
		t.Fatalf("load federated account: %v", err)
	}
	if stored.PasswordHash != nil {
		t.Fatalf("password hash = %v, want NULL", *stored.PasswordHash)
	}
	if stored.HasPassword() {
		t.Fatal("a federated account must not report a password credential")
	}
}

// newIsolatedDatabase migrates a fresh schema, where password_hash is created
// nullable from the start. A real deployment instead has the column already there
// and NOT NULL, so this reconstructs that shape and checks the migration alters it
// in place and leaves the rows alone. Without this, the whole Google path would fail
// at its first insert on every existing installation and pass every test here.
func TestMigrationDropsNotNullOnExistingPasswordColumn(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"

	// Put the column back the way it was before federated sign-in existed.
	if err := isolatedDatabase.Exec(
		"ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL",
	).Error; err != nil {
		t.Fatalf("restore pre-migration column: %v", err)
	}
	seedFederatedUser(t, isolatedDatabase, "usr_pre_migration_0001", "existing@example.com", &hash, now)

	if err := identitypostgres.Migrate(context.Background(), isolatedDatabase); err != nil {
		t.Fatalf("migrate over the pre-migration schema: %v", err)
	}

	var nullable string
	if err := isolatedDatabase.Raw(
		"SELECT is_nullable FROM information_schema.columns "+
			"WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = ?",
		"password_hash",
	).Scan(&nullable).Error; err != nil {
		t.Fatalf("inspect column: %v", err)
	}
	if nullable != "YES" {
		t.Fatalf("password_hash is_nullable = %q, want YES", nullable)
	}

	// The existing row is untouched, and a federated account can now be inserted
	// alongside it.
	var existing identitypostgres.UserModel
	if err := isolatedDatabase.Where("id = ?", "usr_pre_migration_0001").First(&existing).Error; err != nil {
		t.Fatalf("load pre-migration account: %v", err)
	}
	if existing.PasswordHash == nil || *existing.PasswordHash != hash {
		t.Fatalf("migration rewrote an existing password hash: %v", existing.PasswordHash)
	}
	seedFederatedUser(t, isolatedDatabase, "usr_post_migration_001", "federated@example.com", nil, now)
}

// Existing accounts keep their hash. The migration only drops NOT NULL; it must not
// rewrite a single row.
func TestExistingPasswordAccountsSurviveTheNullableMigration(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	store := identitypostgres.NewStore(isolatedDatabase)
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"
	seedFederatedUser(t, isolatedDatabase, "usr_password_account_01", "legacy@example.com", &hash, now)

	stored, err := store.UserByNormalizedEmail(context.Background(), "legacy@example.com")
	if err != nil {
		t.Fatalf("load password account: %v", err)
	}
	if stored.PasswordHash == nil || *stored.PasswordHash != hash {
		t.Fatalf("password hash = %v, want it preserved", stored.PasswordHash)
	}
	if !stored.HasPassword() {
		t.Fatal("a password account must still report a password credential")
	}
}

func TestFederatedIdentityRoundTripAndConstraints(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	store := identitypostgres.NewStore(isolatedDatabase)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	seedFederatedUser(t, isolatedDatabase, "usr_federated_first_001", "first@example.com", nil, now)
	seedFederatedUser(t, isolatedDatabase, "usr_federated_second_01", "second@example.com", nil, now)

	link := identity.FederatedIdentity{
		Provider:            identity.ProviderGoogle,
		Subject:             federatedSubject,
		UserID:              "usr_federated_first_001",
		Email:               "first@example.com",
		CreatedAt:           now,
		LastAuthenticatedAt: now,
	}
	if err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
		return transaction.CreateFederatedIdentity(ctx, link)
	}); err != nil {
		t.Fatalf("create federated identity: %v", err)
	}

	t.Run("round trip", func(t *testing.T) {
		var loaded identity.FederatedIdentity
		if err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			var err error
			loaded, err = transaction.FederatedIdentityForUpdate(ctx, identity.ProviderGoogle, federatedSubject)
			return err
		}); err != nil {
			t.Fatalf("load federated identity: %v", err)
		}
		if loaded.UserID != link.UserID || loaded.Email != link.Email {
			t.Fatalf("loaded link = %+v, want %+v", loaded, link)
		}
	})

	t.Run("unknown subject is not found", func(t *testing.T) {
		err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			_, err := transaction.FederatedIdentityForUpdate(ctx, identity.ProviderGoogle, otherSubject)
			return err
		})
		if !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("unknown subject = %v, want ErrNotFound", err)
		}
	})

	// The composite primary key. One provider account reaches at most one local
	// account, so a subject cannot be re-pointed at somebody else's.
	t.Run("subject cannot be relinked", func(t *testing.T) {
		err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			return transaction.CreateFederatedIdentity(ctx, identity.FederatedIdentity{
				Provider:            identity.ProviderGoogle,
				Subject:             federatedSubject,
				UserID:              "usr_federated_second_01",
				Email:               "second@example.com",
				CreatedAt:           now,
				LastAuthenticatedAt: now,
			})
		})
		if !errors.Is(err, identity.ErrConflict) {
			t.Fatalf("duplicate subject = %v, want ErrConflict", err)
		}
	})

	// The lookup the service uses to refuse a second identity before inserting one,
	// because a constraint violation would abort the transaction and take the
	// refusal's audit event with it.
	t.Run("existing identity for an account is found by user", func(t *testing.T) {
		var loaded identity.FederatedIdentity
		if err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			var err error
			loaded, err = transaction.FederatedIdentityByUserForUpdate(
				ctx, identity.ProviderGoogle, "usr_federated_first_001",
			)
			return err
		}); err != nil {
			t.Fatalf("load identity by user: %v", err)
		}
		if loaded.Subject != federatedSubject {
			t.Fatalf("subject = %q, want %q", loaded.Subject, federatedSubject)
		}

		err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			_, err := transaction.FederatedIdentityByUserForUpdate(
				ctx, identity.ProviderGoogle, "usr_federated_second_01",
			)
			return err
		})
		if !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("unlinked account = %v, want ErrNotFound", err)
		}
	})

	// The per-provider unique index on user_id, which backs the check above. Without
	// it a second Google account could attach to an account it proved nothing about
	// and then sign in as it.
	t.Run("account holds one identity per provider", func(t *testing.T) {
		err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			return transaction.CreateFederatedIdentity(ctx, identity.FederatedIdentity{
				Provider:            identity.ProviderGoogle,
				Subject:             otherSubject,
				UserID:              "usr_federated_first_001",
				Email:               "first@example.com",
				CreatedAt:           now,
				LastAuthenticatedAt: now,
			})
		})
		if !errors.Is(err, identity.ErrConflict) {
			t.Fatalf("second identity for one account = %v, want ErrConflict", err)
		}
	})

	t.Run("touch records the latest sign-in", func(t *testing.T) {
		later := now.Add(time.Hour)
		if err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			return transaction.TouchFederatedIdentity(
				ctx, identity.ProviderGoogle, federatedSubject, "renamed@example.com", later,
			)
		}); err != nil {
			t.Fatalf("touch federated identity: %v", err)
		}
		var stored identitypostgres.FederatedIdentityModel
		if err := isolatedDatabase.Where("subject = ?", federatedSubject).First(&stored).Error; err != nil {
			t.Fatalf("load touched link: %v", err)
		}
		if !stored.LastAuthenticatedAt.Equal(later) || stored.Email != "renamed@example.com" {
			t.Fatalf("touched link = %+v, want the later timestamp and new address", stored)
		}
		// The account's own address is the user's to set, not the provider's.
		var account identitypostgres.UserModel
		if err := isolatedDatabase.Where("id = ?", "usr_federated_first_001").First(&account).Error; err != nil {
			t.Fatalf("load account: %v", err)
		}
		if account.Email != "first@example.com" {
			t.Fatalf("account address = %q, want it untouched by the provider", account.Email)
		}
	})

	t.Run("touching an unknown subject is not found", func(t *testing.T) {
		err := store.WithinTransaction(ctx, func(transaction identity.TransactionStore) error {
			return transaction.TouchFederatedIdentity(
				ctx, identity.ProviderGoogle, otherSubject, "nobody@example.com", now,
			)
		})
		if !errors.Is(err, identity.ErrNotFound) {
			t.Fatalf("touch unknown subject = %v, want ErrNotFound", err)
		}
	})

	// Deleting the account takes the link with it, which is also how a revoked
	// account stops being reachable through Google.
	t.Run("link cascades with its account", func(t *testing.T) {
		if err := isolatedDatabase.
			Where("id = ?", "usr_federated_first_001").
			Delete(&identitypostgres.UserModel{}).Error; err != nil {
			t.Fatalf("delete account: %v", err)
		}
		var remaining int64
		if err := isolatedDatabase.
			Model(&identitypostgres.FederatedIdentityModel{}).
			Count(&remaining).Error; err != nil {
			t.Fatalf("count links: %v", err)
		}
		if remaining != 0 {
			t.Fatalf("%d links survived their account, want 0", remaining)
		}
	})
}

// The provider column is constrained, so a typo or an unreviewed provider name
// fails at the schema rather than silently creating a parallel namespace.
func TestFederatedIdentityRejectsUnknownProvider(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	seedFederatedUser(t, isolatedDatabase, "usr_federated_first_001", "first@example.com", nil, now)

	err := isolatedDatabase.Create(&identitypostgres.FederatedIdentityModel{
		Provider:            "githubb",
		Subject:             federatedSubject,
		UserID:              "usr_federated_first_001",
		Email:               "first@example.com",
		CreatedAt:           now,
		LastAuthenticatedAt: now,
	}).Error
	if err == nil {
		t.Fatal("an unknown provider must be rejected by the schema")
	}
}
