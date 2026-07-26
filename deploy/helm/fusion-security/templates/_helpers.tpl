{{- define "fusion-security.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fusion-security.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "fusion-security.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "fusion-security.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "fusion-security.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fusion-security.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "fusion-mlx.fullname" -}}
{{- printf "%s-mlx" (include "fusion-security.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fusion-mlx.labels" -}}
{{ include "fusion-security.labels" . }}
app.kubernetes.io/component: mlx-backend
{{- end }}

{{- define "fusion-mlx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "fusion-security.name" . }}-mlx
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
