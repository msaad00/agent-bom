{{/*
Expand the name of the chart.
*/}}
{{- define "agent-bom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "agent-bom.labels" -}}
app.kubernetes.io/name: {{ include "agent-bom.name" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "agent-bom.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agent-bom.name" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
