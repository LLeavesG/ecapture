package openssl

import "testing"

func TestParsePackageVersionDumpPrefersActiveUpdatedSystemApp(t *testing.T) {
	dump := `Packages:
  Package [com.example.app] (active):
    codePath=/data/app/com.example.app
    versionCode=301786727 minSdk=32 targetSdk=37
    versionName=17.46.15.sa.arm64

Hidden system packages:
  Package [com.example.app] (factory):
    codePath=/product/priv-app/Example
    versionCode=301606323 minSdk=29 targetSdk=36
    versionName=16.38.63.sa.arm64
`
	name, code, err := parsePackageVersionDump(dump, "com.example.app")
	if err != nil {
		t.Fatal(err)
	}
	if name != "17.46.15.sa.arm64" || code != 301786727 {
		t.Fatalf("selected inactive factory package: name=%q code=%d", name, code)
	}
}

func TestParsePackageVersionDumpLegacyFirstPair(t *testing.T) {
	dump := `versionCode=42 minSdk=24
versionName=4.2
versionCode=7 minSdk=21
versionName=0.7
`
	name, code, err := parsePackageVersionDump(dump, "com.example.legacy")
	if err != nil {
		t.Fatal(err)
	}
	if name != "4.2" || code != 42 {
		t.Fatalf("selected later version pair: name=%q code=%d", name, code)
	}
}

func TestParsePackageVersionDumpRejectsMissingVersion(t *testing.T) {
	if _, _, err := parsePackageVersionDump(
		"Packages:\n  Package [com.example.app] (id):\n",
		"com.example.app",
	); err == nil {
		t.Fatal("missing version unexpectedly accepted")
	}
}
