// Package deploy carries the files sdn-lab installs on a fleet: the host
// preparation and purge scripts, the systemd units and the Prometheus
// configuration. Embedding them lets sdn-lab deploy without a checkout.
package deploy

import "embed"

// Files holds hostprep.sh, purge.sh, systemd/*.service and
// monitoring/prometheus.yml.
//
//go:embed hostprep.sh purge.sh systemd/*.service monitoring/prometheus.yml
var Files embed.FS
