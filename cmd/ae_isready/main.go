// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/owasp-amass/amass/v5/engine/api/client"
)

func main() {
	var hostname string
	var help1, help2 bool

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", path.Base(os.Args[0]), "--host HOSTNAME [-h | -help]")
		return
	}

	flag.BoolVar(&help1, "h", false, "Show the program usage message")
	flag.BoolVar(&help2, "help", false, "Show the program usage message")
	flag.StringVar(&hostname, "host", "", "Hostname or IP address of the Amass Engine")
	flag.Parse()

	if (help1 || help2) || hostname == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", path.Base(os.Args[0]), "--host HOSTNAME")
		flag.PrintDefaults()
		return
	}

	c := client.NewClient("http://" + hostname + ":4000")
	defer c.Close()

	if !c.HealthCheck() {
		// a failure to respond indicates that the server is not yet available
		os.Exit(1)
	}
}
