package main

import "testing"

func TestMainExecute(t *testing.T) {
	rootCmd.SetArgs([]string{"--help"})
	main()
}

func TestServeCmd_PreRun(t *testing.T) {
	if err := serveCmd.Flags().Set("host", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := serveCmd.Flags().Set("port", "9999"); err != nil {
		t.Fatal(err)
	}
	if err := serveCmd.Flags().Set("timeout", "5s"); err != nil {
		t.Fatal(err)
	}
	if err := serveCmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatal(err)
	}
	serveCmd.PreRun(serveCmd, nil)
	if cfg.Server.Host != "1.1.1.1" || cfg.Server.Port != 9999 {
		t.Fatalf("flags not applied")
	}
	serveCmd.Run(serveCmd, nil)
}
