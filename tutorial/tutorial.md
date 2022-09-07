# Attesting Image Scans With Kyverno

This tutorial is based on the following blog post by Chip Zoller: [Attesting Image Scans With Kyverno](https://neonmirrors.net/post/2022-07/attesting-image-scans-kyverno/)

This tutorial details 
- Scan your container image for vulnerabilities
- Generate an attestation with Cosign
- Verify the container image has an attestation with Kyverno

#### Prerequisites
1. Trivy CLI installed
2. Cosign installed 
3. A running Kubernetes cluster that kubectl is connected to

#### Scan Container Image for vulnerabilities

Scan your container image for vulnerabilities and save the scan result to a scan.json file:
```
trivy image --ignore-unfixed --format json --output scan.json anaisurlichs/cns-website:0.0.6
```

* --ignore-unfixed: Ensures that only the vulnerabilities are displayed that have a already a fix available
* --output scan.json: The scan output is scaved to a scan.json file instead of being displayed in the terminal.

Note: Replace the container image with the container image that you would like to scan.

#### Attestation of the vulnerability scan with Cosign

The following command generates an attestation for the vulnerability scan and uploads it to our container image:
```
cosign attest --replace --predicate scan.json --type vuln anaisurlichs/cns-website:0.0.6
```

Note: Replace the container image with the container image that you would like to scan.

#### Kyverno Policy to check attestation

The following policy ensures that the attestation is no older than 168h:

vuln-attestation.yaml
```
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: check-vulnerabilities
spec:
  validationFailureAction: enforce
  webhookTimeoutSeconds: 10
  failurePolicy: Fail
  rules:
    - name: not-older-than-one-week
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "CONTAINER-REGISTRY/*:*"
        attestations:
        - predicateType: cosign.sigstore.dev/attestation/vuln/v1
          conditions:
          - all:
            - key: "{{ time_since('','{{metadata.scanFinishedOn}}','') }}"
              operator: LessThanOrEquals
              value: "168h"
```

#### Apply the policy to your Kubernetes cluster

Ensure that you have Kyverno already deployed and running on your cluster -- for instance throught he Kyverno Helm Chart.

Next, apply the above policy:
```
kubectl apply -f vuln-attestation.yaml
```

To ensure that the policy worked, we can deploye an example deployment file with our container image:

deployment.yaml
```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cns-website
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      run: cns-website
  template:
    metadata:
      labels:
        run: cns-website
    spec:
      containers:
      - name: cns-website
        image: docker.io/anaisurlichs/cns-website:0.0.6
        ports:
          - containerPort: 80
        imagePullPolicy: Always
        resources:
          limits:
            memory: 512Mi
            cpu: 200m
        securityContext:
          allowPrivilegeEscalation: false
```

Once we apply the deployment, it should pass since our attestation is available:
```
kubectl apply -f deployment.yaml -n app
deployment.apps/cns-website created
```

However, if we try to deploy any other container image, our deployment will fail. We can verify this by replacing the image referenced in the deployment with `docker.io/anaisurlichs/cns-website:0.0.5` and applying the deployment:
```
kubectl apply -f deployment-two.yaml

Resource: "apps/v1, Resource=deployments", GroupVersionKind: "apps/v1, Kind=Deployment"
Name: "cns-website", Namespace: "app"
for: "deployment-two.yaml": admission webhook "mutate.kyverno.svc-fail" denied the request: 

resource Deployment/app/cns-website was blocked due to the following policies

check-image:
  autogen-check-image: |
    failed to verify signature for docker.io/anaisurlichs/cns-website:0.0.5: .attestors[0].entries[0].keys: no matching signatures:
```

## Automating the process through GitHub Actions

To automate the above process, we can place the steps into our CI/CD pipeline. Below is the example for GitHub Actions:

```
name: vulnerability-scan
on:
  workflow_dispatch: {}
  schedule:
    - cron: '23 1 * * *' # Every day at 01:23
env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
jobs:
  scan:
    runs-on: ubuntu-20.04
    permissions:
      contents: read
    outputs:
      scan-digest: ${{ steps.calculate-scan-hash.outputs.scan_digest }}
    steps:
    - name: Scan for vulnerabilities
      uses: aquasecurity/trivy-action@1db49f532692e649dc5dc43c7c0444dac4790137 # v0.7.0 (Trivy v0.31.2)
      with: 
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
        format: cosign-vuln
        ignore-unfixed: true
        output: scan.json

    - name: Calculate scan file hash
      id: calculate-scan-hash
      run: |
        SCAN_DIGEST=$(sha256sum scan.json | awk '{print $1}')
        echo "::set-output name=scan_digest::$SCAN_DIGEST"
        echo "Hash of scan.json is: $SCAN_DIGEST"        

    - name: Upload vulnerability scan report
      uses: actions/upload-artifact@3cea5372237819ed00197afe530f5a7ea3e805c8 # v3.1.0
      with:
        name: scan.json
        path: scan.json
        if-no-files-found: error

  attest:
    runs-on: ubuntu-20.04
    permissions:
      contents: write
      actions: read
      packages: write
      id-token: write
    env:
      SCAN_DIGEST: "${{ needs.scan.outputs.scan-digest }}"
    needs: scan
    steps:
    - name: Download scan
      uses: actions/download-artifact@fb598a63ae348fa914e94cd0ff38f362e927b741 # v3.0.0
      with:
        name: scan.json

    - name: Verify scan
      run: |
        set -euo pipefail
        echo "Hash of scan.json should be: $SCAN_DIGEST"
        COMPUTED_HASH=$(sha256sum scan.json | awk '{print $1}')
        echo "The current computed hash for scan.json is: $COMPUTED_HASH"
        echo "If the two above hashes don't match, scan.json has been tampered with."
        echo "$SCAN_DIGEST scan.json" | sha256sum --strict --check --status || exit -2        

    - name: Install Cosign
      uses: sigstore/cosign-installer@09a077b27eb1310dcfb21981bee195b30ce09de0 # v2.5.0
      with:
        cosign-release: v1.10.0

    - name: Log in to GHCR
      uses: docker/login-action@49ed152c8eca782a232dede0303416e8f356c37b # v2.0.0
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Attest Scan
      run: cosign attest --replace --predicate scan.json --type vuln ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
      env:
        COSIGN_EXPERIMENTAL: "true"
```
