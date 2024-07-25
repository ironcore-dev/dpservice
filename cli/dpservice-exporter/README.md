# Prometheus DPDK Exporter

Export Dpservice statistics to Prometheus readable format.

## About this project

`dpservice-exporter` is responsible for monitoring and exposing `dpservice-bin` statistics from [DPDK telemetry](https://doc.dpdk.org/guides/howto/telemetry.html). When run, `dpservice-exporter` creates a simple web server (on a configurable port), on which statistics can be reached. These statistics are updated in configurable time intervals and can be then visualized in dashboard tools like [Grafana](https://grafana.com/). Currently, it provides a solution to get the number of NAT ports used, the number of Virtual services used and other Interface statistics exported as [Prometheus metrics](https://prometheus.io/docs/instrumenting/exposition_formats/).

## Requirements and Setup

`dpservice-bin` needs to be running on the same host to run `dpservice-exporter` and to export the statistics `dpservice-exporter` needs to have access to the socket with the path specified in variable `metrics.SocketPath` *(/var/run/dpdk/rte/dpdk_telemetry.v2)*.
Also specified port (by default 8080) on which we want to run `dpservice-exporter` needs to be available.

## Grafana dashboard

The Grafana dashboard template is located in the folder [dashboard](./dashboard/). It's a JSON file, that can be directly imported into Grafana, just `datasource` and `uid` need to be adjusted based on the environment (marked as `<replace>`).

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/ironcore-dev/dpservice/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information.

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
