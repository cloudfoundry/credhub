## Introduction
The aim of this document is to document the performance of Credhub and measure how it scales horizontally. Multiple Credhub instances are deployed behind a load balancer and are then sent a multitude of requests at a time, while increasing the concurrency of the requests each time. The latencies and throughputs are measured across the above range of requests and plotted in a headroom plot which serves to provide a comparison of expected latency at various various of throughput.
## Benchmarking Setup 
#### Tools: 

* **Hey**: A golang tool which load tests a given endpoint with a given number of requests at a given concurrency and prints the results in a csv file.
* **Matplotlib**: A python graph plotting library which is utilized to generate a headroom plot with data obtained from a provided CSV file.

#### Credhub Instance(s):

AWS m4.large instance

CPU: 2 core

RAM: 8 GiB

#### Database Instance: 

AWS m4.2xlarge instance

CPU: 8 core

RAM: 32 GiB

#### Network Setup:

A test setup is deployed using Bosh on AWS. The deployment is composed of multiple credhub instances(1,2,4 or 10) behind a loadbalancer along with a UAA instance which share a Postgres DB that is deployed in a separate VM. The testing utils are run from a separate isolated instance.

#### Test Setup:

Initial Concurrency: 5

Concurrency Step: 5

Requests/Step: 10,000

No. of test runs/request: 5


> **Deploying Test Setup:**
Instructions on how to deploy the setup for running performance benchmarks against can be found [here](https://github.com/pivotal-cf/credhub-deployments/blob/master/documents/deploying_perf_setup.md).


## Performance Results

## How to build your own Headroom Plot

The tools required to performance test the Credhub performance setup are available [here](https://github.com/cloudfoundry-incubator/credhub-performance).

Follow the instructions provided in the [README](https://github.com/cloudfoundry-incubator/credhub-performance/blob/master/README.md) to both run the tests and process the test output into [Headroom Plots](https://github.com/adrianco/headroom-plot). 
