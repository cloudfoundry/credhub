##Deploying CredHub to Kubernetes

To deploy CredHub to a GCP kubernetes cluster, you will need to:
 1. manually set up a static IP in GCP
 2. overwrite values in `values.yaml`
 2. interpolate the manifest using ytt and then apply the manifest to the cluster

###Setting up the Static IP

Follow the instructions from GCP to set up a static external IP:
https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address

###Configuring CredHub Manifest

You will most likely need to to add and/or override some CredHub application settings. To do this, you can create an `application_config.lib.yml`. 
Here you can add information CredHub will use at runtime! Most importantly, you need to add a UAA user guid so you can log into CredHub!

You will also need to specify the  `load_balancer_ip` in `values.yaml` you configured with GCP!

To apply the CredHub manifest to your kubernetes cluster run the following command:

`ytt -f kubernetes/ | kubectl apply -f -`

This command first interpolates the manifest using ytt, then applies the finalized manifest to the cluster!

###Login To CredHub
To login to CredHub run the command:

`credhub login -s https://<CLUSTER_IP>:9000 -u credhub -p password --ca-cert="$(kubectl get secret server-ca -o json | jq -r .data.certificate | base64 -D)" --ca-cert="$(kubectl get secret uaa-ca -o json | jq -r .data.certificate | base64 -D)"`
