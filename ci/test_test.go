package main

import "testing"

func TestTraefikPluginLogFailureDetectsYaegiImportErrors(t *testing.T) {
	logs := `traefik-1  | {"level":"error","plugins":["captcha-protect"],"error":"failed to create Yaegi interpreter: failed to import plugin code \"github.com/libops/captcha-protect\": 1:21: import \"github.com/libops/captcha-protect\" error: plugins-local/src/github.com/libops/captcha-protect/main.go:304:23: cannot use type func(string,[]string) bool as type func(context.Context,string,[]string) bool in struct literal","time":"2026-06-24T09:18:16Z","message":"Plugins are disabled because an error has occurred."}`

	failure, found := traefikPluginLogFailure(logs)
	if !found {
		t.Fatal("expected Traefik plugin load failure to be detected")
	}
	if failure != "Plugins are disabled" {
		t.Fatalf("expected first detected failure %q, got %q", "Plugins are disabled", failure)
	}
}

func TestTraefikPluginLogFailureAllowsCleanLogs(t *testing.T) {
	logs := `traefik-1  | {"level":"info","message":"Configuration loaded from flags."}`

	if failure, found := traefikPluginLogFailure(logs); found {
		t.Fatalf("did not expect clean logs to fail, got %q", failure)
	}
}
