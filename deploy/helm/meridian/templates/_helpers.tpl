{{/*
Expand the name of the chart.
*/}}
{{- define "meridian.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "meridian.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "meridian.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "meridian.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "meridian.selectorLabels" -}}
app.kubernetes.io/name: {{ include "meridian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Per-component selector labels, e.g. component "control" or "agent".
A workload's spec.selector and its pod template labels must match exactly --
and a selector cannot be changed after creation -- so both read from here.
Takes a dict: (dict "root" . "component" "<name>").
*/}}
{{- define "meridian.componentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "meridian.name" .root }}-{{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{/*
Name of the Secret holding the admission webhook's serving certificate.
Fails rendering when the webhook is enabled without one, rather than
producing a Deployment that crash-loops on a missing volume.
*/}}
{{- define "meridian.webhookCertSecret" -}}
{{- if not .Values.webhook.certSecret -}}
{{- fail "webhook.enabled=true requires webhook.certSecret: the name of a kubernetes.io/tls Secret holding the webhook serving certificate (tls.crt / tls.key)" -}}
{{- end -}}
{{- .Values.webhook.certSecret -}}
{{- end }}
