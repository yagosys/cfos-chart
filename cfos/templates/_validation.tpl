{{/*
Validate KEDA configuration
*/}}
{{- define "cfos.validateKeda" -}}
{{- if .Values.kedaScaling.enabled -}}
  {{- if eq .Values.deployment.kind "DaemonSet" -}}
    {{- fail "KEDA scaling cannot be enabled with DaemonSet deployment kind" -}}
  {{- end -}}
  {{- if not .Values.metrics.service.enabled -}}
    {{- fail "Metrics service must be enabled when using KEDA scaling" -}}
  {{- end -}}
  {{- if not .Values.routeManager.enabled -}}
    {{- fail "Route manager must be enabled for metrics collection with KEDA" -}}
  {{- end -}}
{{- end -}}
{{- end -}}
