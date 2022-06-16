 Continuous integration | License
 -----------------------|--------
[![Unit Tests](https://github.com/kubewarden/safe-annotations-policy/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/kubewarden/safe-annotations-policy/actions/workflows/unit-tests.yml) [![end to end tests](https://github.com/kubewarden/safe-annotations-policy/actions/workflows/e2e-tests.yml/badge.svg)](https://github.com/kubewarden/safe-annotations-policy/actions/workflows/e2e-tests.yml) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)

# How the policy works

This policy validates the annotations of generic Kubernetes objects.

The policy rejects all the resources that use one or more annotations on the
deny list. The deny list is provided by at runtime via the policy configuration.

The policy allows users to put constraints on specific annotations. The constraints
are expressed as regular expression and are provided via the policy settings.

The policy settings look like that:

```yaml
# List of annotations that cannot be used
denied_annotations:
- foo
- bar

# List of annotations that must be defined
mandatory_annotations:
  - cost-center

# Annotations that are validate with user-defined RegExp
# Failing to comply with the RegExp resuls in the object
# being rejected
constrained_annotations:
  priority: "[123]"
  cost-center: "^cc-\\d+$"
```

> **Note well:** the regular expression must be expressed
> using [Go's syntax](https://golang.org/pkg/regexp/syntax/).

Given the configuration from above, the policy would reject the creation
of this Pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  annotations:
    foo: hello world
spec:
  containers:
    - name: nginx
      image: nginx:latest
```

The policy would also reject the creation of this Ingress resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: minimal-ingress
  annotations:
    cost-center: cc-marketing
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80
```

Policy's settings can also be used to force certain annotations to be specified,
regardless of their contents:

```yaml
# Policy's settings

constrained_annotations:
  mandatory-annotation: ".*" # <- this annotation must be present, we don't care about its value
```

# Obtain policy

The policy is automatically published as an OCI artifact inside of
[this](https://github.com/orgs/kubewarden/packages/container/package/policies%2Fsafe-annotations)
container registry.

# Using the policy

The easiest way to use this policy is through the [kubewarden-controller](https://github.com/kubewarden/kubewarden-controller).

# Testing

This policy comes with a set of unit tests implemented using the Go testing
framework.

As usual, the tests are defined inside of the `_test.go` files. Given these
tests are not part of the final WebAssembly binary, the official Go compiler
can be used to run them. Hence they can take advantage of the `encoding/json`
package to reduce some testing boiler plate.

The unit tests can be run via a simple command:

```shell
make test
```

It's also important the test the final result of the TinyGo compilation:
the actual WebAssembly module.

This is done by a second set of end-to-end tests. These tests use the
`policicy-testdrive` cli provided by the Kubewarden project to load and execute
the policy.

The e2e tests are implemented using [bats](https://github.com/sstephenson/bats):
the Bash Automated Testing System.

The end-to-end tests are defined inside of the `e2e.bats` file and can
be run via this commmand:

```shell
make e2e-tests
```
