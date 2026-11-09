package workloadsecurity

import (
	"context"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/validation"
)

const criticalRuleFile = "workload-privileged-hostpath-escape.yaml"
const mediumRuleFile = "workload-escape-risk-hostpath-mount.yaml"

// loadRule loads a single SpotterRule from the given file name in this directory and
// validates it the same way the real loader/validator pipeline does, failing the test
// immediately if the rule is malformed.
func loadRule(t *testing.T, fileName string) *models.SpotterRule {
	t.Helper()

	path := filepath.Join(".", fileName)
	result, err := parser.LoadFromFile(path)
	if err != nil {
		t.Fatalf("failed to load %s: %v", fileName, err)
	}
	if len(result.Errors) > 0 {
		t.Fatalf("errors loading %s: %v", fileName, result.Errors)
	}
	if len(result.Rules) != 1 {
		t.Fatalf("expected exactly 1 rule in %s, got %d", fileName, len(result.Rules))
	}

	rule := result.Rules[0]
	validationResult := validation.ValidateSpotterRule(rule)
	if !validationResult.Valid {
		t.Fatalf("rule %s failed validation: %v", fileName, validationResult.Errors)
	}

	return rule
}

// mustParseObject parses a YAML Kubernetes manifest into the unstructured
// map[string]interface{} shape the CEL engine expects as "object".
func mustParseObject(t *testing.T, manifest string) map[string]interface{} {
	t.Helper()

	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &obj); err != nil {
		t.Fatalf("failed to parse manifest YAML: %v", err)
	}
	return obj
}

// evaluate compiles and runs rule against object using the real CEL engine used in
// production (pkg/engine.CELEngine), returning the ValidationResult. A nil result means
// the resource did not match the rule's selector criteria at all.
func evaluate(t *testing.T, rule *models.SpotterRule, object map[string]interface{}) *models.ValidationResult {
	t.Helper()

	celEngine, err := engine.NewCELEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	result, err := celEngine.EvaluateRule(context.Background(), rule, object)
	if err != nil {
		t.Fatalf("failed to evaluate rule %s: %v", rule.GetID(), err)
	}
	return result
}

// TestPrivilegedHostPathEscape_CriticalPrivilegedDockerSock covers the CRITICAL case:
// a privileged container mounts /var/run/docker.sock by hostPath. The CRITICAL rule
// (spotter-workload-010) must fire; the MEDIUM rule (spotter-workload-011) must not,
// since the two rules are designed to be mutually exclusive for the same resource.
func TestPrivilegedHostPathEscape_CriticalPrivilegedDockerSock(t *testing.T) {
	criticalRule := loadRule(t, criticalRuleFile)
	mediumRule := loadRule(t, mediumRuleFile)

	pod := mustParseObject(t, `
apiVersion: v1
kind: Pod
metadata:
  name: docker-escape
  namespace: default
spec:
  containers:
    - name: app
      image: busybox
      securityContext:
        privileged: true
      volumeMounts:
        - name: dsock
          mountPath: /var/run/docker.sock
  volumes:
    - name: dsock
      hostPath:
        path: /var/run/docker.sock
`)

	criticalResult := evaluate(t, criticalRule, pod)
	if criticalResult == nil {
		t.Fatal("expected CRITICAL rule to match resource, got nil (selector mismatch)")
	}
	if criticalResult.Passed {
		t.Fatal("expected CRITICAL rule to detect violation (Passed=false), got Passed=true")
	}
	if criticalResult.Severity != models.SeverityCritical {
		t.Fatalf("expected severity %q, got %q", models.SeverityCritical, criticalResult.Severity)
	}

	mediumResult := evaluate(t, mediumRule, pod)
	if mediumResult == nil {
		t.Fatal("expected MEDIUM rule to match resource (selector), got nil")
	}
	if !mediumResult.Passed {
		t.Fatal("expected MEDIUM rule to NOT flag a resource already covered by the CRITICAL rule, but it reported a violation")
	}
}

// TestPrivilegedHostPathEscape_NonSensitiveMountNoHit covers the "no match" baseline:
// a container mounts a plain, non-sensitive hostPath and is not privileged. Neither
// rule should report a violation.
func TestPrivilegedHostPathEscape_NonSensitiveMountNoHit(t *testing.T) {
	criticalRule := loadRule(t, criticalRuleFile)
	mediumRule := loadRule(t, mediumRuleFile)

	pod := mustParseObject(t, `
apiVersion: v1
kind: Pod
metadata:
  name: benign
  namespace: default
spec:
  containers:
    - name: app
      image: busybox
      volumeMounts:
        - name: data
          mountPath: /data
  volumes:
    - name: data
      hostPath:
        path: /var/lib/myapp/data
`)

	criticalResult := evaluate(t, criticalRule, pod)
	if criticalResult != nil && !criticalResult.Passed {
		t.Fatalf("expected CRITICAL rule to not flag a benign non-sensitive mount, got violation: %s", criticalResult.Message)
	}

	mediumResult := evaluate(t, mediumRule, pod)
	if mediumResult != nil && !mediumResult.Passed {
		t.Fatalf("expected MEDIUM rule to not flag a benign non-sensitive mount, got violation: %s", mediumResult.Message)
	}
}

// TestPrivilegedHostPathEscape_MediumNonPrivilegedDockerSock covers the MEDIUM case:
// docker.sock is mounted via hostPath, but the mounting container is NOT privileged
// and has no equivalent capability. This must downgrade to MEDIUM instead of CRITICAL.
func TestPrivilegedHostPathEscape_MediumNonPrivilegedDockerSock(t *testing.T) {
	criticalRule := loadRule(t, criticalRuleFile)
	mediumRule := loadRule(t, mediumRuleFile)

	pod := mustParseObject(t, `
apiVersion: v1
kind: Pod
metadata:
  name: nonprivileged-dockersock
  namespace: default
spec:
  containers:
    - name: app
      image: busybox
      volumeMounts:
        - name: dsock
          mountPath: /var/run/docker.sock
  volumes:
    - name: dsock
      hostPath:
        path: /var/run/docker.sock
`)

	criticalResult := evaluate(t, criticalRule, pod)
	if criticalResult != nil && !criticalResult.Passed {
		t.Fatalf("expected CRITICAL rule to NOT fire without a privileged/capability-escalated container, got violation: %s", criticalResult.Message)
	}

	mediumResult := evaluate(t, mediumRule, pod)
	if mediumResult == nil {
		t.Fatal("expected MEDIUM rule to match resource, got nil")
	}
	if mediumResult.Passed {
		t.Fatal("expected MEDIUM rule to detect the non-privileged docker.sock mount as a violation")
	}
	if mediumResult.Severity != models.SeverityMedium {
		t.Fatalf("expected severity %q, got %q", models.SeverityMedium, mediumResult.Severity)
	}
}

// TestPrivilegedHostPathEscape_DaemonSetTemplatePath covers the DaemonSet PodSpec path
// (object.spec.template.spec), confirming the same CEL expression used for Pod also
// correctly reaches into a DaemonSet's pod template without any kind-specific rule.
func TestPrivilegedHostPathEscape_DaemonSetTemplatePath(t *testing.T) {
	criticalRule := loadRule(t, criticalRuleFile)

	daemonSet := mustParseObject(t, `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: agent
          image: busybox
          securityContext:
            privileged: true
          volumeMounts:
            - name: dsock
              mountPath: /var/run/docker.sock
      volumes:
        - name: dsock
          hostPath:
            path: /var/run/docker.sock
`)

	result := evaluate(t, criticalRule, daemonSet)
	if result == nil {
		t.Fatal("expected CRITICAL rule to match DaemonSet resource, got nil (selector mismatch)")
	}
	if result.Passed {
		t.Fatal("expected CRITICAL rule to detect violation in DaemonSet pod template, got Passed=true")
	}
	if result.Severity != models.SeverityCritical {
		t.Fatalf("expected severity %q, got %q", models.SeverityCritical, result.Severity)
	}
}

// TestPrivilegedHostPathEscape_CronJobNestedTemplatePath covers the CronJob PodSpec
// path (object.spec.jobTemplate.spec.template.spec), the deepest nesting among the
// supported kinds, using the same shared CEL expression.
func TestPrivilegedHostPathEscape_CronJobNestedTemplatePath(t *testing.T) {
	criticalRule := loadRule(t, criticalRuleFile)

	cronJob := mustParseObject(t, `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-job
  namespace: default
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: busybox
              securityContext:
                privileged: true
              volumeMounts:
                - name: dsock
                  mountPath: /var/run/docker.sock
          volumes:
            - name: dsock
              hostPath:
                path: /var/run/docker.sock
`)

	result := evaluate(t, criticalRule, cronJob)
	if result == nil {
		t.Fatal("expected CRITICAL rule to match CronJob resource, got nil (selector mismatch)")
	}
	if result.Passed {
		t.Fatal("expected CRITICAL rule to detect violation in CronJob's nested jobTemplate.spec.template.spec, got Passed=true")
	}
	if result.Severity != models.SeverityCritical {
		t.Fatalf("expected severity %q, got %q", models.SeverityCritical, result.Severity)
	}
}
