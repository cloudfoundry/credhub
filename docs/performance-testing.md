## Introduction
The aim of this document is to document the performance of Credhub and measure how it scales horizontally. Multiple Credhub instances are deployed behind a load balancer and are then sent a multitude of requests at a time, while increasing the concurrency of the requests each time. The latencies and throughputs are measured across the above range of requests and plotted in a headroom plot which serves to provide a comparison of expected latency at various various of throughput.
## Benchmarking Setup 
#### Tools: 

* **Hey**: A golang tool which load tests a given endpoint with a given number of requests at a given concurrency and prints the results in a csv file. We use a forked version of hey that enables mtls and start time measurement.
* **Matplotlib**: A python graph plotting library which is utilized to generate a headroom plot with data obtained from a provided CSV file.

#### Credhub Instance(s):
AWS m4.large instance
CPU: 2 core
RAM: 8 GiB
Encryption Provider: Internal
Max Heap Size: 6GiB
Authentication: Mutual TLS
DataStorage Require TLS: False
ACL Enabled: False
#### Database Instance: 
AWS: db.m4.2xlarge instance
CPU: 8 core
RAM: 32 GiB
Deployment: RDS
Allocated Storage: 50 GiB
Availability Zone: Same as other infrastructure
Engine: postgres
EngineVersion: 9.4.11
MultiAZ: false
StorageType: gp2

#### Network Setup:
All the VMs are deployed in the same AZ on AWS. The credhub instance are deployed behind a load balancer and are each assigned an ephemeral public IP. The UAA is assigned an elastic IP which is used by the Credhub for communication. Ensure the security group UAA is in allows external traffic. An alternative approach would be to assign each Credhub instance an elastic IP and allow traffic from those IPs on UAA's firewall/security group rules.
The internal postgres instance is only provided an internal IP which both Credhub and UAA utilize to communicate with it.

The performance testing toolkit is a bosh release which is deployed on an m4.large VM which lives in the same AZ as the Credhub cluster. It interacts with the Credhub cluster using mtls. Ensure the required certificates are passed to the deployment for communication with Credhub.

Client and Server TLS connections are terminated in the application and not in Load Balancers or a TLS termination proxy.

#### Test Setup:

The test setup is available as a BOSH release that is deployed in the same AZ as the Credhub deployment.

The test bench communicates with Credhub using MTLS over the network. 

Initial Concurrency: 5

Concurrency Step: 5

Max Concurrency: [Recommended values will be updated as we get some numbers from our tests.]

Requests/Step: 10,000

No. of test runs/request: 5

## Performance Results

## How to build your own Headroom Plot

The tools required to performance test the Credhub performance setup are available [here](https://github.com/cloudfoundry-incubator/credhub-performance).

Follow the instructions provided in the [README](https://github.com/cloudfoundry-incubator/credhub-performance/blob/master/README.md) to both run the tests and process the test output into [Headroom Plots](https://github.com/adrianco/headroom-plot). 
