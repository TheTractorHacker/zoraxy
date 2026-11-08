package zorxauth

import (
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/database"
)

// With a custom -conf folder, group policies and branding must be stored below it,
// including when the saved options still carry the old hard coded ./conf default.
func TestConfigFolderFollowsConfFlag(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "data", "sso", "zorxauth")
	old := DefaultConfigFolder
	DefaultConfigFolder = custom
	defer func() { DefaultConfigFolder = old }()

	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "z.db"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// options persisted by an older build
	db.NewTable(DB_NAME)
	legacy := getDefaultOptions()
	legacy.ConfigFolderPath = LegacyConfigFolder
	db.Write(DB_NAME, "options", legacy)

	ar := NewAuthRouter(db, nil)
	defer ar.Close()
	if ar.Options.ConfigFolderPath != custom {
		t.Fatalf("ConfigFolderPath = %q, want %q", ar.Options.ConfigFolderPath, custom)
	}
	if got := ar.groupPolicyFolder(); filepath.Dir(got) != custom {
		t.Fatalf("group policy folder %q not below %q", got, custom)
	}
}
